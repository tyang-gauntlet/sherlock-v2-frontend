import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from services.solidity_analyzer import analyze_solidity_files
from services.github_repo_manager import GithubRepoManager
from services.embedding_processor import EmbeddingProcessor
import shutil
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Pinecone as LangchainPinecone
from langchain_community.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langsmith.run_helpers import traceable
from pinecone import Pinecone
from datetime import datetime
import statistics
from typing import List, Dict, Any
import numpy as np
from langchain.schema import Document
from langchain_community.embeddings import OpenAIEmbeddings

load_dotenv()

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
CORS(app)

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
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-mpnet-base-v2")

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


@app.route('/rag/analyze', methods=['POST'])
@traceable(run_type="chain", name="vulnerability_analysis")
def analyze_with_rag():
    """Analyze code using RAG pipeline with LangChain and LangSmith logging"""
    try:
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

        code = data['code']
        print(f"Analyzing code snippet: {code[:100]}...")

        # Get similar vulnerabilities
        print("Querying vector store...")
        results = qa_chain.invoke(
            {"query": code}
        )
        print("Vector store query completed")

        # Extract source documents and their metadata
        source_docs = results.get("source_documents", [])
        print(f"Found {len(source_docs)} similar documents")

        # Process similar vulnerabilities
        similar_vulnerabilities = []
        for doc in source_docs:
            metadata = doc.metadata
            if metadata.get('type') == 'vulnerability_code':
                similar_vulnerabilities.append({
                    'repo_name': metadata.get('repo_name'),
                    'report_file': metadata.get('report_file'),
                    'severity': metadata.get('severity'),
                    'category': metadata.get('category'),
                    'code_snippet': metadata.get('code_snippet', ''),
                    'context': metadata.get('context', ''),
                    'file_path': metadata.get('file_path', ''),
                    'start_line': metadata.get('start_line'),
                    'end_line': metadata.get('end_line'),
                    'similarity_score': metadata.get('score', 0.0) if isinstance(metadata.get('score'), (int, float)) else 0.0
                })

        # Calculate similarity statistics
        similarities = [
            doc.metadata.get("score", 0.0) if isinstance(
                doc.metadata.get("score"), (int, float)) else 0.0
            for doc in source_docs
        ]

        # Ensure we have valid numbers for statistics
        valid_similarities = [s for s in similarities if s > 0]
        similarity_stats = calculate_similarity_stats(valid_similarities)
        print(f"Similarity stats: {similarity_stats}")

        # Return the analysis results
        return jsonify({
            'analysis': results['result'],
            'similar_vulnerabilities': similar_vulnerabilities,
            'statistics': {
                'similarity_stats': similarity_stats,
                'total_vectors_retrieved': len(source_docs)
            }
        })

    except Exception as e:
        print(f"Error in analyze_with_rag: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/analyze', methods=['POST'])
def analyze_code():
    print("Received analyze request")

    # Validate request
    if 'files' not in request.files and 'github_url' not in request.form:
        print("No files or GitHub URL provided")
        return jsonify({'error': 'No files or GitHub URL provided'}), 400

    saved_files = []
    file_details = []
    temp_dir = None

    try:
        if 'files' in request.files:
            files = request.files.getlist('files')
            print(f"Received {len(files)} files")

            if not files or not any(file.filename for file in files):
                print("No valid files selected")
                return jsonify({'error': 'No valid files selected'}), 400

            # Create upload directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            for file in files:
                if not file or not file.filename:
                    continue

                print(f"Processing file: {file.filename}")
                if allowed_file(file.filename):
                    try:
                        filename = secure_filename(file.filename)
                        filepath = os.path.join(
                            app.config['UPLOAD_FOLDER'], filename)
                        print(f"Saving file to: {filepath}")
                        file.save(filepath)

                        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                            saved_files.append(filepath)
                            file_details.append({
                                'name': filename,
                                'path': filepath,
                                'size': os.path.getsize(filepath),
                                'repo_type': 'uploaded'
                            })
                        else:
                            print(
                                f"Error: File {filename} was not saved properly")
                    except Exception as save_error:
                        print(
                            f"Error saving file {filename}: {str(save_error)}")
                else:
                    print(f"Invalid file type: {file.filename}")

        if not saved_files and 'github_url' not in request.form:
            print("No valid files processed")
            return jsonify({
                'error': 'No valid Solidity files were uploaded. Please upload .sol files only.',
                'status': 'error'
            }), 400

        # Process GitHub repository if URL provided
        if 'github_url' in request.form:
            github_url = request.form['github_url']
            print(f"Processing GitHub repository: {github_url}")

            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                return jsonify({'error': 'GitHub token not configured'}), 500

            try:
                repo_manager = GithubRepoManager(github_token)
                temp_dir = os.path.join(
                    app.config['UPLOAD_FOLDER'], 'github_repos')
                os.makedirs(temp_dir, exist_ok=True)

                # Process main repository
                base_repo_name = github_url.split('/')[-1]
                base_repo_info = {
                    "name": base_repo_name,
                    "clone_url": github_url,
                    "is_judging": False
                }

                base_repo_dir = os.path.join(temp_dir, 'codebase')
                os.makedirs(base_repo_dir, exist_ok=True)

                if not repo_manager.clone_repository(base_repo_info, base_repo_dir):
                    return jsonify({'error': 'Failed to clone repository'}), 500

                # Process Solidity files
                for item in repo_manager.process_repository_content(base_repo_info, base_repo_dir):
                    if item["type"] == "solidity_file":
                        relative_path = item["file_path"]
                        full_path = os.path.join(base_repo_dir, relative_path)
                        dir_name = os.path.dirname(relative_path)

                        if os.path.exists(full_path) and os.path.getsize(full_path) > 0:
                            saved_files.append(full_path)
                            file_details.append({
                                'name': relative_path,
                                'path': full_path,
                                'size': os.path.getsize(full_path),
                                'repo_type': 'codebase',
                                'directory': dir_name if dir_name else 'root'
                            })

            except Exception as github_error:
                print(
                    f"Error processing GitHub repository: {str(github_error)}")
                return jsonify({
                    'error': f'Failed to process GitHub repository: {str(github_error)}',
                    'status': 'error'
                }), 500

        if not saved_files:
            return jsonify({
                'error': 'No valid Solidity files found to analyze',
                'status': 'error'
            }), 400

        # Perform the analysis
        try:
            print("Starting analysis")
            analysis_results = analyze_solidity_files(saved_files)

            if 'error' in analysis_results:
                return jsonify({
                    'error': analysis_results['error'],
                    'status': 'error'
                }), 500

            # Add file metadata to results
            if 'files' not in analysis_results:
                analysis_results['files'] = []
            analysis_results['files'].extend(file_details)

            return jsonify(analysis_results), 200

        except Exception as analysis_error:
            print(f"Analysis error: {str(analysis_error)}")
            return jsonify({
                'error': f'Analysis failed: {str(analysis_error)}',
                'files': file_details,
                'status': 'error'
            }), 500

    except Exception as e:
        print(f"Server error: {str(e)}")
        return jsonify({
            'error': f'Server error: {str(e)}',
            'status': 'error'
        }), 500

    finally:
        # Clean up
        print("Starting cleanup...")
        for filepath in saved_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f"Cleaned up file: {filepath}")
            except Exception as cleanup_error:
                print(f"Error removing file {filepath}: {str(cleanup_error)}")

        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                print(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as cleanup_error:
                print(
                    f"Error removing temporary directory: {str(cleanup_error)}")

        print("Cleanup completed")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5001)))
