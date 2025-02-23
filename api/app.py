import os
from flask import Flask, request, jsonify
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

# Update CORS configuration to allow all origins during development
CORS(app,
     resources={
         r"/*": {
             "origins": ["http://localhost:3000", "http://localhost:5001"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True
         }
     })


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
        text_key="code_snippet"
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

# Initialize QA chain
qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(
        search_kwargs={
            "k": 10,  # Get more results
            "filter": {"type": "vulnerability_code"}
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

Evaluate:
1. How relevant is this vulnerability to the code being analyzed? (0-100%)
2. What specific parts of the code make it vulnerable or safe from this issue?
3. Are there any mitigating factors present in the code?

Format your response EXACTLY as the following JSON (no other text):
{{
    "relevance_score": <number between 0 and 100>,
    "explanation": "<detailed explanation>",
    "affected_code_regions": ["<specific code region 1>", "<specific code region 2>", ...],
    "risk_level": "<HIGH|MEDIUM|LOW|NONE>",
    "confidence": <number between 0 and 100>
}}""",
            input_variables=["code", "category", "description", "similar_code"]
        )
        eval_chain = LLMChain(llm=llm, prompt=eval_prompt)

        # Run evaluation
        print(
            f"Evaluating vulnerability: {vulnerability.get('category', 'Unknown')}")
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
                # Remove any leading/trailing whitespace and newlines
                cleaned_text = result['text'].strip()
                # Remove any markdown code block markers
                cleaned_text = cleaned_text.replace(
                    '```json', '').replace('```', '')
                evaluation = json.loads(cleaned_text)
            else:
                raise ValueError(f"Invalid result format: {result}")

            # Validate required fields
            required_fields = ['relevance_score', 'explanation',
                               'affected_code_regions', 'risk_level', 'confidence']
            missing_fields = [
                field for field in required_fields if field not in evaluation]
            if missing_fields:
                raise ValueError(f"Missing required fields: {missing_fields}")

            # Ensure numeric fields are within valid ranges
            relevance_score = float(evaluation['relevance_score'])
            if not 0 <= relevance_score <= 100:
                relevance_score = max(0, min(100, relevance_score))

            confidence = float(evaluation['confidence'])
            if not 0 <= confidence <= 100:
                confidence = max(0, min(100, confidence))

            # Normalize risk level
            risk_level = evaluation['risk_level'].upper()
            if risk_level not in ['HIGH', 'MEDIUM', 'LOW', 'NONE']:
                risk_level = 'UNKNOWN'

            return {
                "relevance_score": relevance_score / 100.0,
                "explanation": evaluation["explanation"],
                "affected_regions": evaluation["affected_code_regions"],
                "risk_level": risk_level,
                "confidence": confidence / 100.0
            }

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Error parsing evaluation result: {e}")
            print(f"Raw result: {result}")
            # Provide default values that won't break the frontend
            return {
                "relevance_score": 0.0,
                "explanation": "Could not evaluate relevance due to parsing error",
                "affected_regions": [],
                "risk_level": "UNKNOWN",
                "confidence": 0.0
            }

    except Exception as e:
        print(f"Error in relevance evaluation: {e}")
        return {
            "relevance_score": 0.0,
            "explanation": "Error occurred during evaluation",
            "affected_regions": [],
            "risk_level": "UNKNOWN",
            "confidence": 0.0
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


@app.route('/rag/analyze', methods=['POST', 'OPTIONS'])
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

            # Get similar vulnerabilities with metadata
            print("Querying vector store...")
            results = qa_chain.invoke({"query": code_file['content']})
            print(f"RAG Analysis results: {results}")

            if not results or not isinstance(results, dict):
                print(f"Invalid results format: {results}")
                continue

            # Extract source documents and their metadata
            source_docs = results.get("source_documents", [])
            print(f"Found {len(source_docs)} similar documents")

            # Process each document individually
            analyzed_documents = []
            for doc in source_docs:
                # Cleanup memory periodically
                if len(analyzed_documents) % 5 == 0:
                    cleanup_memory()

                metadata = doc.metadata
                if metadata.get('type') == 'vulnerability_code':
                    # Create document analysis object
                    doc_analysis = {
                        'document_id': metadata.get('id', 'unknown'),
                        'metadata': {
                            'repo_name': metadata.get('repo_name'),
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
                            'code_snippet': metadata.get('code_snippet', ''),
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
                    print(
                        f"Evaluating relevance for document {doc_analysis['document_id']}")
                    evaluation = evaluate_vulnerability_relevance(code_file['content'], {
                        'category': metadata.get('category'),
                        'context': metadata.get('context', ''),
                        'code_snippet': metadata.get('code_snippet', '')
                    }, llm)
                    print(f"Relevance evaluation result: {evaluation}")

                    # Add evaluation results
                    doc_analysis['evaluation'] = {
                        'relevance_score': evaluation['relevance_score'],
                        'explanation': evaluation['explanation'],
                        'affected_regions': evaluation['affected_regions'],
                        'risk_level': evaluation['risk_level'],
                        'confidence': evaluation['confidence']
                    }

                    analyzed_documents.append(doc_analysis)

            # Sort documents by relevance score
            analyzed_documents.sort(
                key=lambda x: x['evaluation']['relevance_score'], reverse=True)

            # Calculate statistics for this file
            similarity_scores = [doc['similarity']['score']
                                 for doc in analyzed_documents]
            relevance_scores = [doc['evaluation']['relevance_score']
                                for doc in analyzed_documents]
            confidence_scores = [doc['evaluation']['confidence']
                                 for doc in analyzed_documents]

            file_statistics = {
                'similarity_stats': calculate_similarity_stats(similarity_scores),
                'relevance_stats': calculate_similarity_stats(relevance_scores),
                'confidence_stats': calculate_similarity_stats(confidence_scores),
                'total_documents_retrieved': len(analyzed_documents),
                'total_documents_analyzed': len(analyzed_documents),
                'risk_level_distribution': {
                    'HIGH': len([d for d in analyzed_documents if d['evaluation']['risk_level'] == 'HIGH']),
                    'MEDIUM': len([d for d in analyzed_documents if d['evaluation']['risk_level'] == 'MEDIUM']),
                    'LOW': len([d for d in analyzed_documents if d['evaluation']['risk_level'] == 'LOW']),
                    'NONE': len([d for d in analyzed_documents if d['evaluation']['risk_level'] == 'NONE'])
                },
                'category_distribution': {}
            }

            # Calculate category distribution
            for doc in analyzed_documents:
                category = doc['metadata']['category']
                if category:
                    if category not in file_statistics['category_distribution']:
                        file_statistics['category_distribution'][category] = {
                            'count': 0,
                            'avg_relevance': 0.0,
                            'avg_similarity': 0.0
                        }
                    stats = file_statistics['category_distribution'][category]
                    stats['count'] += 1
                    stats['avg_relevance'] += doc['evaluation']['relevance_score']
                    stats['avg_similarity'] += doc['similarity']['score']

            # Finalize category averages
            for category_stats in file_statistics['category_distribution'].values():
                if category_stats['count'] > 0:
                    category_stats['avg_relevance'] /= category_stats['count']
                    category_stats['avg_similarity'] /= category_stats['count']

            # Add file results
            all_results.append({
                'file_name': code_file['name'],
                'analysis_summary': results.get('result', ''),
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

        print(f"Sending response with {len(all_results)} analyzed files")
        return jsonify(response_data)

    except Exception as e:
        cleanup_memory()
        print(f"Error in analyze_with_rag: {str(e)}")
        import traceback
        traceback.print_exc()
        error_response = jsonify({'error': str(e)})
        return error_response, 500


@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({'status': 'healthy'}), 200


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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

        # Save uploaded files
        file_paths = []
        for file in files:
            if file.filename == '':
                continue
            if file and file.filename.endswith('.sol'):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                file_paths.append(file_path)

        if not file_paths:
            return jsonify({'error': 'No valid Solidity files uploaded'}), 400

        # Analyze files
        results = analyze_solidity_files(file_paths)

        # Clean up uploaded files
        for file_path in file_paths:
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error removing file {file_path}: {e}")

        # Check if there was an error during analysis
        if 'error' in results:
            return jsonify({'error': results['error']}), 500

        return jsonify(results), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5001)))
