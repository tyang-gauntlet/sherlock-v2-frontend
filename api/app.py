import os
import json
import subprocess
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from services.solidity_analyzer import analyze_solidity_files
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import shutil
from sentence_transformers import SentenceTransformer
from langchain.embeddings.base import Embeddings
from langchain_community.vectorstores import Pinecone as LangchainPinecone
from langchain_community.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA, LLMChain
from langchain.prompts import PromptTemplate
from langsmith.run_helpers import traceable
from pinecone import Pinecone
from datetime import datetime
import statistics
from typing import List, Dict, Any, Optional
import numpy as np
from langchain.schema import Document
import gc
import psutil
import resource
try:
    import torch
except ImportError:
    torch = None

load_dotenv()


class CustomHuggingFaceEmbeddings(Embeddings):
    def __init__(self, model_name: str = "sentence-transformers/all-mpnet-base-v2"):
        self.model = SentenceTransformer(model_name)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of documents using the HuggingFace model"""
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    def embed_query(self, text: str) -> List[float]:
        """Embed a query using the HuggingFace model"""
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()


# Initialize LangSmith
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
langchain_api_key = os.getenv("LANGCHAIN_API_KEY")
if langchain_api_key:
    os.environ["LANGCHAIN_API_KEY"] = langchain_api_key
    os.environ["LANGCHAIN_PROJECT"] = "sherlock-vulnerability-analysis"
else:
    print("Warning: LANGCHAIN_API_KEY not set. LangSmith tracing will be disabled.")
    os.environ["LANGCHAIN_TRACING_V2"] = "false"

app = Flask(__name__)

# Configure CORS to allow credentials and handle preflight requests
CORS(app, 
     resources={
         r"/*": {
             "origins": ["http://localhost:3000"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
             "supports_credentials": True,
             "expose_headers": ["Content-Type", "Authorization"],
             "max_age": 600
         }
     })

# Add CORS preflight handler for all routes
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Requested-With")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'sol', 'json'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize Pinecone
print("Initializing Pinecone...")
pc = Pinecone(api_key=os.getenv('PINECONE_API_KEY'))

# Initialize embeddings
print("Initializing embeddings...")
embeddings = CustomHuggingFaceEmbeddings()

# Initialize vector store
print("Initializing vector store...")
try:
    vectorstore = LangchainPinecone.from_existing_index(
        index_name="smartsmart",
        embedding=embeddings,
        text_key="code_snippet",
        namespace=""  # Explicitly set empty namespace since that's where our vectors are
    )
    print("Vector store initialized successfully")
    # Get index stats
    index = pc.Index("smartsmart")
    stats = index.describe_index_stats()
    print(f"Index stats: {stats}")
except Exception as e:
    print(f"Error initializing vector store: {e}")
    vectorstore = None

# Initialize LLM
llm = ChatOpenAI(
    model_name="gpt-4",
    temperature=0,
    openai_api_key=os.getenv("OPENAI_API_KEY")
)

# Custom prompt template for vulnerability analysis
VULNERABILITY_PROMPT = """You are a smart contract security expert. Analyze the following code and potential vulnerabilities:

Context: Here are some similar vulnerabilities found in other smart contracts:
{context}

Code to analyze: {question}

Provide a detailed analysis including:
1. Whether the identified similar vulnerabilities are relevant to this code
2. The specific parts of the code that might be vulnerable
3. Severity assessment
4. Recommended mitigations

Analysis:"""

# Initialize QA chain with optimized retrieval
qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(
        search_kwargs={
            "k": 5,  # Match the direct query count
            "namespace": ""  # Explicitly set empty namespace
        }
    ),
    chain_type_kwargs={
        "prompt": PromptTemplate(
            template=VULNERABILITY_PROMPT,
            input_variables=["context", "question"]
        )
    },
    return_source_documents=True
)


@traceable(run_type="chain", name="relevance_evaluation")
def evaluate_vulnerability_relevance(code: str, vulnerability: dict, llm: ChatOpenAI) -> dict:
    """Evaluate the relevance of a vulnerability to the given code."""
    try:
        # Create evaluation chain with a more structured prompt
        eval_prompt = PromptTemplate(
            template="""You are a smart contract security expert. Evaluate the relevance of a potential vulnerability to the given code.

Code being analyzed:
{code}

Potential vulnerability:
Category: {category}
Description: {description}
Similar code: {similar_code}

Evaluate the following carefully:
1. Relevance Score (0-100):
   - 0-20: No relevance or completely different context
   - 21-40: Slight relevance but different implementation
   - 41-60: Moderate relevance with some similar patterns
   - 61-80: High relevance with similar implementation
   - 81-100: Direct match or very high relevance
   Consider: code patterns, implementation details, security implications

2. What specific parts of the code make it vulnerable or safe from this issue?
   - Identify exact functions, lines, or patterns
   - Consider both vulnerable and protective code elements

3. Mitigating Factors:
   - Security measures present
   - Implementation differences
   - Context variations

Format your response EXACTLY as the following JSON (no other text):
{{
    "relevance_score": <detailed score between 0-100 based on the scoring guide above>,
    "explanation": "<detailed explanation of the score and reasoning>",
    "affected_code_regions": ["<specific code region 1>", "<specific code region 2>", ...],
    "risk_level": "<HIGH|MEDIUM|LOW|NONE>",
    "confidence": <confidence in assessment 0-100>
}}""",
            input_variables=["code", "category", "description", "similar_code"]
        )
        eval_chain = LLMChain(llm=llm, prompt=eval_prompt)

        # Run evaluation
        print(f"Evaluating vulnerability: {vulnerability.get('category', 'Unknown')}")
        result = eval_chain.invoke({
            "code": code,
            "category": vulnerability.get('category', 'Unknown'),
            "description": vulnerability.get('context', ''),
            "similar_code": vulnerability.get('code_snippet', '')
        })
        print(f"Raw evaluation result: {result}")

        # Parse the result
        try:
            import json
            # Clean up the response text to ensure valid JSON
            if isinstance(result, dict) and 'text' in result:
                cleaned_text = result['text'].strip()
                cleaned_text = cleaned_text.replace('```json', '').replace('```', '')
                evaluation = json.loads(cleaned_text)
            else:
                raise ValueError(f"Invalid result format: {result}")

            # Validate required fields
            required_fields = ['relevance_score', 'explanation', 'affected_code_regions', 'risk_level', 'confidence']
            missing_fields = [field for field in required_fields if field not in evaluation]
            if missing_fields:
                raise ValueError(f"Missing required fields: {missing_fields}")

            # Ensure numeric fields are within valid ranges and maintain granularity
            relevance_score = float(evaluation['relevance_score'])
            if not 0 <= relevance_score <= 100:
                relevance_score = max(0, min(100, relevance_score))
            
            # Don't normalize the relevance score to 0-1 range
            relevance_score = round(relevance_score, 2)  # Keep 2 decimal precision

            confidence = float(evaluation['confidence'])
            if not 0 <= confidence <= 100:
                confidence = max(0, min(100, confidence))
            confidence = round(confidence, 2)  # Keep 2 decimal precision

            # Normalize risk level
            risk_level = evaluation['risk_level'].upper()
            if risk_level not in ['HIGH', 'MEDIUM', 'LOW', 'NONE']:
                risk_level = 'UNKNOWN'

            return {
                "relevance_score": relevance_score,  # Keep as 0-100 score
                "explanation": evaluation["explanation"],
                "affected_regions": evaluation["affected_code_regions"],
                "risk_level": risk_level,
                "confidence": confidence
            }

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Error parsing evaluation result: {e}")
            print(f"Raw result: {result}")
            # Provide more meaningful default values
            return {
                "relevance_score": 25.0,  # Default to low-moderate relevance instead of 0
                "explanation": "Could not evaluate relevance due to parsing error. Defaulting to low-moderate relevance score.",
                "affected_regions": [],
                "risk_level": "UNKNOWN",
                "confidence": 30.0  # Low confidence due to error
            }

    except Exception as e:
        print(f"Error in relevance evaluation: {e}")
        return {
            "relevance_score": 25.0,  # Default to low-moderate relevance instead of 0
            "explanation": f"Error occurred during evaluation: {str(e)}. Defaulting to low-moderate relevance score.",
            "affected_regions": [],
            "risk_level": "UNKNOWN",
            "confidence": 30.0  # Low confidence due to error
        }


def calculate_similarity_stats(similarities: List[float]) -> Dict[str, float]:
    """Calculate statistics for similarity scores"""
    if not similarities:
        return {
            "mean": 0.0,
            "median": 0.0,
            "std_dev": 0.0,
            "min": 0.0,
            "max": 0.0
        }

    try:
        # Convert all values to float to ensure consistent types
        similarities = [float(s) for s in similarities]
        return {
            "mean": float(statistics.mean(similarities)),
            "median": float(statistics.median(similarities)),
            "std_dev": float(statistics.stdev(similarities)) if len(similarities) > 1 else 0.0,
            "min": float(min(similarities)),
            "max": float(max(similarities))
        }
    except (ValueError, statistics.StatisticsError):
        # Return zeros if there's any error calculating statistics
        return {
            "mean": 0.0,
            "median": 0.0,
            "std_dev": 0.0,
            "min": 0.0,
            "max": 0.0
        }


def limit_memory():
    """Set memory limits for the process"""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        # Set soft limit to 1GB or 75% of the hard limit, whichever is smaller
        new_soft = min(1024 * 1024 * 1024, int(hard * 0.75))
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, hard))
    except Exception as e:
        print(f"Warning: Could not set memory limit: {e}")


def cleanup_memory():
    """Force garbage collection and clear memory"""
    gc.collect()
    if torch is not None and hasattr(torch, 'cuda'):
        torch.cuda.empty_cache()


@traceable(run_type="chain", name="vulnerability_analysis")
def analyze_with_rag():
    """Analyze code using RAG pipeline with LangChain and LangSmith logging"""
    try:
        # Set memory limits
        limit_memory()

        # Handle preflight request
        if request.method == 'OPTIONS':
            return '', 204

        # Check required environment variables
        if not os.getenv('OPENAI_API_KEY'):
            print("Error: OPENAI_API_KEY not set")
            return jsonify({'error': 'OpenAI API key not configured'}), 500

        if not os.getenv('PINECONE_API_KEY'):
            print("Error: PINECONE_API_KEY not set")
            return jsonify({'error': 'Pinecone API key not configured'}), 500

        if not vectorstore:
            print("Error: Vector store not initialized")
            return jsonify({'error': 'Vector store not initialized'}), 500

        data = request.json
        if not data or 'code' not in data:
            print("Error: No code provided in request")
            return jsonify({'error': 'No code provided'}), 400

        code_files = data['code']
        if not isinstance(code_files, list):
            print("Error: Code must be an array of files")
            return jsonify({'error': 'Code must be an array of files'}), 400

        # Process each file
        all_results = []
        for code_file in code_files:
            if not isinstance(code_file, dict) or 'name' not in code_file or 'content' not in code_file:
                print("Error: Invalid file format")
                continue

            print(f"Analyzing file {code_file['name']}...")

            # Split content into smaller chunks for better retrieval
            chunks = split_content_into_chunks(code_file['content'])
            all_docs = []

            for chunk in chunks:
                # Get similar vulnerabilities with metadata
                print(f"\nQuerying vector store for chunk of size {len(chunk)}...")
                print(f"Chunk content preview: {chunk[:200]}...")
                
                # In analyze_with_rag function, update the search logic:
                print("\nTrying direct similarity search...")
                try:
                    # Generate query embedding
                    query_embedding = embeddings.embed_query(chunk)
                    print(f"\nQuery embedding shape: {len(query_embedding)}")
                    print(f"Query embedding preview: {query_embedding[:5]}...")

                    # First try direct Pinecone query
                    print("\nExecuting direct Pinecone query...")
                    query_response = index.query(
                        vector=query_embedding,
                        top_k=5,
                        namespace="",
                        include_metadata=True
                    )
                    
                    print(f"\nDirect Pinecone query found {len(query_response.matches)} matches")
                    
                    # Convert Pinecone results to Documents and add to all_docs
                    for match in query_response.matches:
                        print(f"\nProcessing match with score: {match.score}")
                        print(f"Match metadata: {match.metadata}")
                        
                        # Create Document with complete metadata
                        doc = Document(
                            page_content=match.metadata.get('content', match.metadata.get('code_snippet', '')),
                            metadata={
                                **match.metadata,
                                'score': match.score,
                                'repo_name': match.metadata.get('repo_name', 'unknown'),
                                'type': match.metadata.get('type', 'unknown'),
                                'category': match.metadata.get('category', 'unknown')
                            }
                        )
                        all_docs.append(doc)
                        print(f"Added document from repo: {doc.metadata.get('repo_name')}")

                except Exception as e:
                    print(f"Error in direct Pinecone query: {e}")
                    # If direct query fails, try LangChain's similarity search
                    try:
                        print("\nFalling back to LangChain similarity search...")
                        direct_results = vectorstore.similarity_search(
                            chunk,
                            k=5
                        )
                        print(f"LangChain similarity search found {len(direct_results)} results")
                        all_docs.extend(direct_results)
                    except Exception as e2:
                        print(f"Error in LangChain similarity search: {e2}")

                # Now try the QA chain with accumulated documents
                if all_docs:
                    print(f"\nProcessing {len(all_docs)} documents with QA chain...")
                    try:
                        results = qa_chain.invoke({
                            "query": chunk,
                            "context": "\n\n".join(doc.page_content for doc in all_docs[:5])  # Use top 5 docs for context
                        })
                        
                        if isinstance(results, dict):
                            print("QA chain analysis completed successfully")
                            if 'answer' in results:
                                print(f"Analysis result: {results['answer'][:200]}...")
                        else:
                            print(f"Unexpected QA chain result format: {type(results)}")
                    except Exception as e:
                        print(f"Error in QA chain: {e}")
                else:
                    print("No documents found for analysis")

            # Process all documents without deduplication
            analyzed_documents = []
            seen_repos = set()

            for doc in all_docs:
                # Cleanup memory periodically
                if len(analyzed_documents) % 5 == 0:
                    cleanup_memory()

                metadata = doc.metadata
                # Process all documents, not just vulnerability_code type
                repo_name = metadata.get('repo_name', '')
                seen_repos.add(repo_name)

                # Create document analysis object
                doc_analysis = {
                    'document_id': metadata.get('id', 'unknown'),
                    'metadata': {
                        'repo_name': repo_name,
                        'report_file': metadata.get('report_file'),
                        'file_path': metadata.get('file_path'),
                        'commit_hash': metadata.get('commit_hash'),
                        'timestamp': metadata.get('timestamp'),
                        'type': metadata.get('type'),
                        'category': metadata.get('category'),
                        'severity': metadata.get('severity'),
                        'start_line': metadata.get('start_line'),
                        'end_line': metadata.get('end_line')
                    },
                    'content': {
                        'code_snippet': doc.page_content,  # Use full content
                        'context': metadata.get('context', ''),
                        'description': metadata.get('description', '')
                    },
                    'similarity': {
                        'score': metadata.get('score', 0.0) if isinstance(metadata.get('score'), (int, float)) else 0.0,
                        'vector_id': metadata.get('vector_id'),
                        'embedding_model': "sentence-transformers/all-mpnet-base-v2",
                        'embedding_dimension': 768
                    }
                }

                # Evaluate relevance
                print(f"\nEvaluating relevance for document {doc_analysis['document_id']} from repo {repo_name}")
                evaluation = evaluate_vulnerability_relevance(code_file['content'], {
                    'category': metadata.get('category', 'Unknown'),
                    'context': metadata.get('context', ''),
                    'code_snippet': doc.page_content
                }, llm)

                # Add evaluation results
                doc_analysis['evaluation'] = evaluation
                analyzed_documents.append(doc_analysis)
                print(f"Evaluation results: {evaluation}")

            # Add OpenAI analysis
            for doc in analyzed_documents:
                doc['openai_analysis'] = analyze_retrieved_document(doc, code_file['content'], llm)

            print(f"\nRetrieved and analyzed {len(analyzed_documents)} documents from {len(seen_repos)} different repositories: {', '.join(seen_repos)}")

            # Sort documents by relevance score and diversity
            analyzed_documents = sort_by_relevance_and_diversity(
                analyzed_documents)

            # Calculate statistics for this file
            file_statistics = calculate_file_statistics(analyzed_documents)

            # Add repository diversity metrics
            file_statistics['repository_stats'] = {
                'total_repos': len(seen_repos),
                'repos': list(seen_repos)
            }

            # Add file results
            all_results.append({
                'file_name': code_file['name'],
                'analysis_summary': generate_analysis_summary(analyzed_documents, file_statistics),
                'analyzed_documents': analyzed_documents,
                'statistics': file_statistics
            })

        # Return the enhanced analysis results
        response_data = {
            'files': all_results,
            'model_info': {
                'embedding_model': "sentence-transformers/all-mpnet-base-v2",
                'llm_model': "gpt-4",
                'embedding_dimension': 768,
                'timestamp': datetime.now().isoformat()
            }
        }

        return jsonify(response_data)

    except Exception as e:
        cleanup_memory()
        print(f"Error in analyze_with_rag: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def split_content_into_chunks(content: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """Split content into overlapping chunks for better retrieval."""
    chunks = []
    start = 0
    content_length = len(content)

    while start < content_length:
        end = min(start + chunk_size, content_length)
        # If this is not the first chunk, include some overlap
        if start > 0:
            start = max(0, start - overlap)
        chunks.append(content[start:end])
        start = end

    return chunks


def deduplicate_documents(docs: List[Document]) -> List[Document]:
    """Remove duplicate documents based on their IDs or content."""
    seen_ids = set()
    seen_contents = set()
    unique_docs = []

    for doc in docs:
        doc_id = doc.metadata.get('id', '')
        content = doc.page_content if hasattr(doc, 'page_content') else str(doc)
        
        # If we have an ID and haven't seen it before
        if doc_id and doc_id not in seen_ids:
            seen_ids.add(doc_id)
            seen_contents.add(content)
            unique_docs.append(doc)
        # If we don't have an ID but haven't seen this content before
        elif not doc_id and content not in seen_contents:
            seen_contents.add(content)
            unique_docs.append(doc)

    return unique_docs


def sort_by_relevance_and_diversity(documents: List[Dict]) -> List[Dict]:
    """Sort documents by relevance score while maintaining repository diversity."""
    # Group documents by repository
    repos_docs = {}
    for doc in documents:
        repo = doc['metadata']['repo_name']
        if repo not in repos_docs:
            repos_docs[repo] = []
        repos_docs[repo].append(doc)

    # Sort within each repository
    for repo in repos_docs:
        repos_docs[repo].sort(key=lambda x: x['evaluation']
                              ['relevance_score'], reverse=True)

    # Interleave results from different repositories
    final_results = []
    while any(repos_docs.values()):
        for repo in list(repos_docs.keys()):
            if repos_docs[repo]:
                final_results.append(repos_docs[repo].pop(0))
            else:
                del repos_docs[repo]

    return final_results


def generate_analysis_summary(documents: List[Dict], statistics: Dict) -> str:
    """Generate a comprehensive analysis summary."""
    repos = statistics['repository_stats']['repos']
    total_vulns = len(documents)

    summary = f"Analysis based on {total_vulns} similar vulnerabilities found across {len(repos)} repositories. "

    if documents:
        # Get top categories
        categories = {}
        for doc in documents:
            cat = doc['metadata']['category']
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1

        top_categories = sorted(
            categories.items(), key=lambda x: x[1], reverse=True)[:3]
        summary += f"Main vulnerability categories identified: {', '.join(cat for cat, _ in top_categories)}. "

        # Add risk distribution
        risk_levels = statistics['risk_level_distribution']
        if risk_levels['HIGH'] > 0:
            summary += f"Found {risk_levels['HIGH']} high-risk vulnerabilities. "
        if risk_levels['MEDIUM'] > 0:
            summary += f"Found {risk_levels['MEDIUM']} medium-risk vulnerabilities. "

    return summary.strip()


@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({'status': 'healthy'}), 200


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def install_solc_version(version: str) -> bool:
    """Install a specific version of solc."""
    try:
        # Remove caret, greater than, or less than symbols
        clean_version = version.replace('^', '').replace(
            '>=', '').replace('<=', '').replace('>', '').replace('<', '')

        # Install the version
        subprocess.run(['solc-select', 'install', clean_version], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing solc version {version}: {e}")
        return False


def use_solc_version(version: str) -> bool:
    """Set the active solc version."""
    try:
        # Remove caret, greater than, or less than symbols
        clean_version = version.replace('^', '').replace(
            '>=', '').replace('<=', '').replace('>', '').replace('<', '')

        # Set the version
        subprocess.run(['solc-select', 'use', clean_version], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error setting solc version {version}: {e}")
        return False


def get_installed_solc_versions() -> list:
    """Get list of installed solc versions."""
    try:
        result = subprocess.run(
            ['solc-select', 'versions'], capture_output=True, text=True, check=True)
        return result.stdout.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error getting installed versions: {e}")
        return []


def extract_version_from_file(file_path: str) -> str:
    """Extract Solidity version from a file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            import re
            version_match = re.search(
                r'pragma solidity\s+(\^?\d+\.\d+\.\d+|>=?\d+\.\d+\.\d+|<=?\d+\.\d+\.\d+)', content)
            if version_match:
                return version_match.group(1)
    except Exception as e:
        print(f"Error extracting version from {file_path}: {e}")
    return None


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze uploaded Solidity files for vulnerabilities."""
    try:
        # Check if files were uploaded
        if 'files' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400

        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No files selected'}), 400

        # Get Solidity versions from request
        solidity_versions = []
        if 'solidity_versions' in request.form:
            try:
                solidity_versions = json.loads(
                    request.form['solidity_versions'])
            except json.JSONDecodeError:
                return jsonify({'error': 'Invalid solidity_versions format'}), 400

        # Save uploaded files and track their versions
        file_paths = []
        file_versions = {}

        for file in files:
            if file.filename == '':
                continue
            if file and file.filename.endswith('.sol'):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                file_paths.append(file_path)

                # Extract version from file if not provided
                version = None
                if solidity_versions:
                    version = solidity_versions[len(file_versions)]
                if not version:
                    version = extract_version_from_file(file_path)
                if version:
                    file_versions[file_path] = version

        if not file_paths:
            return jsonify({'error': 'No valid Solidity files uploaded'}), 400

        # Get unique versions needed
        unique_versions = set(file_versions.values())

        # Check and install required versions
        installed_versions = get_installed_solc_versions()
        for version in unique_versions:
            clean_version = version.replace('^', '').replace(
                '>=', '').replace('<=', '').replace('>', '').replace('<', '')
            if clean_version not in installed_versions:
                if not install_solc_version(clean_version):
                    return jsonify({'error': f'Failed to install Solidity version {clean_version}'}), 500

        # Group files by version
        files_by_version = {}
        for file_path, version in file_versions.items():
            clean_version = version.replace('^', '').replace(
                '>=', '').replace('<=', '').replace('>', '').replace('<', '')
            if clean_version not in files_by_version:
                files_by_version[clean_version] = []
            files_by_version[clean_version].append(file_path)

        # Analyze files version by version
        all_results = {
            'vulnerabilities': [],
            'total_files_analyzed': 0,
            'total_vulnerabilities': 0,
            'total_contracts': 0,
            'total_functions': 0,
            'successful_analyses': 0,
            'overall_risk_level': 'LOW',
            'analysis_details': []
        }

        for version, version_files in files_by_version.items():
            # Set the correct version
            if not use_solc_version(version):
                return jsonify({'error': f'Failed to set Solidity version {version}'}), 500

            # Analyze files for this version
            version_results = analyze_solidity_files(version_files)

            # Merge results
            if 'error' not in version_results:
                all_results['vulnerabilities'].extend(
                    version_results.get('vulnerabilities', []))
                all_results['total_files_analyzed'] += version_results.get(
                    'total_files_analyzed', 0)
                all_results['total_vulnerabilities'] += version_results.get(
                    'total_vulnerabilities', 0)
                all_results['total_contracts'] += version_results.get(
                    'total_contracts', 0)
                all_results['total_functions'] += version_results.get(
                    'total_functions', 0)
                all_results['successful_analyses'] += version_results.get(
                    'successful_analyses', 0)
                all_results['analysis_details'].extend(
                    version_results.get('analysis_details', []))

        # Determine overall risk level
        if all_results['total_vulnerabilities'] > 0:
            high_severity = any(v.get('impact', '').upper(
            ) == 'HIGH' for v in all_results['vulnerabilities'])
            medium_severity = any(v.get('impact', '').upper(
            ) == 'MEDIUM' for v in all_results['vulnerabilities'])

            if high_severity:
                all_results['overall_risk_level'] = 'HIGH'
            elif medium_severity:
                all_results['overall_risk_level'] = 'MEDIUM'

        # Clean up uploaded files
        for file_path in file_paths:
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error removing file {file_path}: {e}")

        return jsonify(all_results), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/rag/analyze', methods=['POST', 'OPTIONS'])
def rag_analyze():
    """Endpoint for RAG-based code analysis."""
    return analyze_with_rag()


def calculate_file_statistics(documents: List[Dict]) -> Dict:
    """Calculate enhanced statistics for a file's analysis results."""
    stats = {
        'total_documents': len(documents),
        'risk_level_distribution': {
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'NONE': 0,
            'UNKNOWN': 0
        },
        'vulnerability_types': {},
        'relevance_scores': [],
        'confidence_scores': [],
        'relevant_matches': 0,
        'irrelevant_matches': 0,
        'average_confidence': 0.0,
        'repositories': set(),
        'vulnerability_patterns': {}
    }

    for doc in documents:
        # Basic stats from before
        risk_level = doc.get('evaluation', {}).get('risk_level', 'UNKNOWN')
        stats['risk_level_distribution'][risk_level] += 1
        
        # Enhanced stats
        if doc.get('openai_analysis'):
            analysis = doc['openai_analysis']
            
            # Track relevant vs irrelevant matches
            if analysis.get('is_relevant'):
                stats['relevant_matches'] += 1
            else:
                stats['irrelevant_matches'] += 1
                
            # Track vulnerability types and patterns
            for vuln in analysis.get('identified_vulnerabilities', []):
                vuln_name = vuln.get('name', 'Unknown')
                if vuln_name not in stats['vulnerability_types']:
                    stats['vulnerability_types'][vuln_name] = {
                        'count': 0,
                        'severities': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0},
                        'confidence_scores': []
                    }
                stats['vulnerability_types'][vuln_name]['count'] += 1
                severity = vuln.get('severity', 'UNKNOWN').upper()
                if severity not in stats['vulnerability_types'][vuln_name]['severities']:
                    severity = 'UNKNOWN'
                stats['vulnerability_types'][vuln_name]['severities'][severity] += 1
                
            # Track confidence scores
            if analysis.get('confidence_score'):
                stats['confidence_scores'].append(analysis['confidence_score'])
                
        # Track repositories
        if doc.get('metadata', {}).get('repo_name'):
            stats['repositories'].add(doc['metadata']['repo_name'])
            
    # Calculate averages and summaries
    if stats['confidence_scores']:
        stats['average_confidence'] = sum(stats['confidence_scores']) / len(stats['confidence_scores'])
    
    stats['total_repositories'] = len(stats['repositories'])
    stats['repositories'] = list(stats['repositories'])
    
    return stats


def analyze_retrieved_document(doc: Dict, code_context: str, llm: ChatOpenAI) -> Dict:
    """Analyze a retrieved document for vulnerabilities using OpenAI."""
    analysis_prompt = PromptTemplate(
        template="""As a smart contract security expert, analyze this potential vulnerability match:

Code being analyzed:
{code_context}

Retrieved similar code/vulnerability:
{retrieved_content}

Metadata:
{metadata}

Analyze and provide:
1. Is this a relevant match? Why or why not?
2. What specific vulnerabilities might be present? Categorize them into one of these types:
   - REENTRANCY
   - ACCESS_CONTROL
   - ARITHMETIC
   - TIMESTAMP_DEPENDENCY
   - UNCHECKED_CALLS
   - DELEGATECALL
   - SELF_DESTRUCT
   - DENIAL_OF_SERVICE
   - FRONT_RUNNING
   - ORACLE_MANIPULATION
   - FLASH_LOAN
   - SIGNATURE_REPLAY
   - INITIALIZATION
   - UPGRADEABLE
   - GAS_OPTIMIZATION
   - LOGIC_ERROR
3. How severe are they? (Must be one of: HIGH, MEDIUM, LOW, UNKNOWN)
4. What are the recommended fixes?

Format your response as JSON:
{{
    "is_relevant": true/false,
    "relevance_explanation": "explanation",
    "identified_vulnerabilities": [
        {{
            "name": "vulnerability name (MUST be one of the categories above)",
            "severity": "HIGH/MEDIUM/LOW/UNKNOWN",
            "description": "description",
            "fix": "recommended fix"
        }}
    ],
    "confidence_score": 0-100
}}"""
    )

    try:
        result = llm.invoke(analysis_prompt.format(
            code_context=code_context,
            retrieved_content=doc.get('content', {}).get('code_snippet', ''),
            metadata=json.dumps(doc.get('metadata', {}), indent=2)
        ))
        
        # Parse the response
        try:
            if isinstance(result, dict) and 'text' in result:
                analysis = json.loads(result['text'].strip())
            else:
                analysis = json.loads(str(result).strip())

            # Validate and normalize vulnerability categories
            if 'identified_vulnerabilities' in analysis:
                for vuln in analysis['identified_vulnerabilities']:
                    if 'name' in vuln:
                        # Convert to uppercase and replace spaces with underscores
                        vuln['name'] = vuln['name'].upper().replace(' ', '_')
                        
                        # Map similar categories to standardized ones
                        category_mapping = {
                            'OWNERSHIP': 'ACCESS_CONTROL',
                            'OWNER': 'ACCESS_CONTROL',
                            'PERMISSIONS': 'ACCESS_CONTROL',
                            'ROLES': 'ACCESS_CONTROL',
                            'MATH': 'ARITHMETIC',
                            'OVERFLOW': 'ARITHMETIC',
                            'UNDERFLOW': 'ARITHMETIC',
                            'TIME': 'TIMESTAMP_DEPENDENCY',
                            'BLOCK_TIMESTAMP': 'TIMESTAMP_DEPENDENCY',
                            'UNSAFE_CALL': 'UNCHECKED_CALLS',
                            'UNSAFE_DELEGATECALL': 'DELEGATECALL',
                            'SELFDESTRUCT': 'SELF_DESTRUCT',
                            'DOS': 'DENIAL_OF_SERVICE',
                            'FRONTRUNNING': 'FRONT_RUNNING',
                            'PRICE_MANIPULATION': 'ORACLE_MANIPULATION',
                            'FLASHLOAN': 'FLASH_LOAN',
                            'REPLAY': 'SIGNATURE_REPLAY',
                            'INIT': 'INITIALIZATION',
                            'PROXY': 'UPGRADEABLE',
                            'GAS': 'GAS_OPTIMIZATION',
                            'BUSINESS_LOGIC': 'LOGIC_ERROR'
                        }
                        
                        # Map to standard category if a similar one is found
                        for similar, standard in category_mapping.items():
                            if similar in vuln['name']:
                                vuln['name'] = standard
                                break

                    # Normalize severity to be one of the allowed values
                    if 'severity' in vuln:
                        severity = vuln['severity'].upper()
                        if severity not in ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                            vuln['severity'] = 'UNKNOWN'
                        else:
                            vuln['severity'] = severity
                    else:
                        vuln['severity'] = 'UNKNOWN'
            
            return analysis

        except json.JSONDecodeError as e:
            print(f"Error parsing LLM response: {e}")
            print(f"Raw response: {result}")
            return {
                "is_relevant": False,
                "relevance_explanation": "Error parsing analysis response",
                "identified_vulnerabilities": [{
                    "name": "LOGIC_ERROR",
                    "severity": "UNKNOWN",
                    "description": f"Error parsing analysis response: {str(e)}",
                    "fix": "Unable to provide fix due to analysis error"
                }],
                "confidence_score": 0
            }

    except Exception as e:
        print(f"Error in vulnerability analysis: {e}")
        return {
            "is_relevant": False,
            "relevance_explanation": f"Error in analysis: {str(e)}",
            "identified_vulnerabilities": [{
                "name": "LOGIC_ERROR",
                "severity": "UNKNOWN",
                "description": f"Error occurred during analysis: {str(e)}",
                "fix": "Unable to provide fix due to analysis error"
            }],
            "confidence_score": 0
        }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5001)))
