#!/bin/bash

echo "🚀 Starting local test of embedding system..."

# Check if .env exists and has required variables
echo "🔍 Checking environment variables..."
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found in local directory!"
    exit 1
fi

# Verify required environment variables
required_vars=("PINECONE_API_KEY" "GITHUB_TOKEN" "OPENAI_API_KEY")
missing_vars=()
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ $line =~ ^[^#] ]]; then  # Skip comments
        for var in "${required_vars[@]}"; do
            if [[ $line == "$var="* ]]; then
                if [[ $line == "$var=" || $line == "$var=''" || $line == "$var=\"\"" ]]; then
                    missing_vars+=("$var")
                fi
            fi
        done
    fi
done < .env

if [ ${#missing_vars[@]} -ne 0 ]; then
    echo "❌ Error: The following required environment variables are empty:"
    printf '%s\n' "${missing_vars[@]}"
    exit 1
fi

# Set up Python environment
echo "🐍 Setting up Python environment..."

# Create and activate virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Copy .env to api directory
echo "📦 Copying .env file..."
cp .env api/.env

echo "📦 Installing dependencies..."
cd api

# Upgrade pip and install build tools
pip install --upgrade pip setuptools wheel

# Install core dependencies using pre-built wheels where possible
pip install --only-binary :all: 'numpy<2.0'
pip install --only-binary :all: 'torch==2.2.0+cpu' -f https://download.pytorch.org/whl/cpu/torch_stable.html
pip install --only-binary :all: 'tokenizers==0.15.2'
pip install --only-binary :all: 'transformers==4.38.1'
pip install --only-binary :all: 'sentence-transformers==2.5.1'

# Pre-download the model to avoid timeout issues
echo "📦 Pre-downloading sentence transformer model..."
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('flax-sentence-embeddings/st-codesearch-distilroberta-base')"

# Install remaining requirements but skip the ML packages we already installed
pip install -r <(grep -v 'torch\|transformers\|sentence-transformers\|numpy\|tokenizers' requirements.txt)

echo "🔧 Verifying environment..."
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found in api directory!"
    exit 1
fi

echo "📋 Environment contents:"
ls -la
echo "📋 Services directory contents:"
ls -la services/

echo "🧪 Testing environment setup..."
python -c 'import torch; import numpy; import pinecone; print("NumPy version:", numpy.__version__); print("Torch version:", torch.__version__); print("Pinecone package version:", pinecone.__version__)'

echo "🔧 Testing DNS resolution and Pinecone connection..."
python -c "
from pinecone import Pinecone
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize Pinecone
pc = Pinecone(api_key=os.getenv('PINECONE_API_KEY'))

# Test connection by listing indexes
indexes = pc.list_indexes()
print('✅ Successfully connected to Pinecone')
print('Available indexes:', indexes)
"

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to connect to Pinecone. Please check your environment variables and network connectivity."
    exit 1
fi

echo "🧪 Running test on Tally repositories..."
PYTHONPATH=. python scripts/process_sherlock_repos.py 2024-11-tally 2024-11-tally-judging

echo "🔍 Testing vector search functionality..."
# Create a test script to verify embeddings
cat > verify_embeddings.py << 'EOL'
from services.embedding_processor import EmbeddingProcessor
import os
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

def test_vector_search():
    # Initialize embedding processor
    embedding_processor = EmbeddingProcessor(
        os.getenv('PINECONE_API_KEY'),
        "us-east-1-aws",
        'smartsmart'
    )
    
    # Test code to analyze for vulnerabilities
    test_code = {
        "content": """
        function transfer(address to, uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
        """,
        "repo_name": "test_repo",
        "file_path": "test.sol",
        "directory": "contracts"
    }
    
    # Analyze the test code
    vulnerabilities = embedding_processor.analyze_code_for_vulnerabilities(test_code)
    
    # Print results
    print("\nVector Search Results:")
    print("=====================")
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\nPotential Vulnerability #{i}:")
            print(f"Code Location: Lines {vuln['code_location']['start_line']}-{vuln['code_location']['end_line']}")
            print("\nSimilar Known Vulnerabilities:")
            for similar in vuln['similar_vulnerabilities']:
                print(f"\n- Title: {similar['title']}")
                print(f"  Severity: {similar['severity']}")
                print(f"  Category: {similar['category']}")
                print(f"  Repository: {similar['repo_name']}")
                print(f"  Similarity Score: {similar['similarity_score']:.2f}")
    else:
        print("No similar vulnerabilities found")

if __name__ == "__main__":
    test_vector_search()
EOL

echo "Running vector search test..."
PYTHONPATH=. python verify_embeddings.py

# Clean up
echo "🧹 Cleaning up..."
rm verify_embeddings.py
rm .env  # Remove the copied .env file from api directory

echo "✅ Local testing completed!" 