#!/bin/bash

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

# SSH options for better timeout handling
SSH_OPTS="-o ConnectTimeout=10 -o ServerAliveInterval=60 -o ServerAliveCountMax=10"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Starting deployment and test of embedding system..."

# Test SSH connection first
echo "🔍 Testing SSH connection..."
if ! ssh -i $KEY_PATH $SSH_OPTS $EC2_USER@$EC2_HOST "echo '✅ SSH connection successful'"; then
    echo "❌ Error: Cannot connect to EC2 instance. Please check:"
    echo "  1. EC2 instance is running"
    echo "  2. Security group allows SSH access"
    echo "  3. Key file path is correct"
    exit 1
fi

# Check if .env exists locally and has required variables
echo "🔍 Checking environment variables..."
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found in local directory!"
    exit 1
fi

# Verify required environment variables
required_vars=("PINECONE_API_KEY" "PINECONE_ENVIRONMENT" "GITHUB_TOKEN" "OPENAI_API_KEY")
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

# Create the application directory on EC2
echo "📁 Creating application directory..."
if ! ssh -i $KEY_PATH $SSH_OPTS $EC2_USER@$EC2_HOST "
    set -x  # Enable command tracing
    mkdir -p $REMOTE_DIR/api
    mkdir -p $REMOTE_DIR/api/services
    mkdir -p $REMOTE_DIR/api/scripts
    mkdir -p ~/.cache/torch/sentence_transformers
"; then
    echo "❌ Error: Failed to create directories on EC2"
    exit 1
fi

# Copy the .env file first and verify
echo "📦 Copying .env file..."
if ! scp -i $KEY_PATH $SSH_OPTS .env $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/.env; then
    echo "❌ Error: Failed to copy .env file"
    exit 1
fi

# Verify .env file was copied
echo "🔍 Verifying .env file..."
if ! ssh -i $KEY_PATH $SSH_OPTS $EC2_USER@$EC2_HOST "
    if [ ! -f $REMOTE_DIR/api/.env ]; then
        echo '❌ Error: .env file not found in api directory!'
        exit 1
    fi
    echo '✅ .env file copied successfully'
"; then
    echo "❌ Error: Failed to verify .env file"
    exit 1
fi

# Copy the project files with correct structure
echo "📦 Copying project files to EC2..."
if ! scp -i $KEY_PATH $SSH_OPTS -r ./api/services/* $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/services/; then
    echo "❌ Error: Failed to copy services directory"
    exit 1
fi

if ! scp -i $KEY_PATH $SSH_OPTS -r ./api/scripts/* $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/scripts/; then
    echo "❌ Error: Failed to copy scripts directory"
    exit 1
fi

if ! scp -i $KEY_PATH $SSH_OPTS ./api/app.py ./api/requirements.txt $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/; then
    echo "❌ Error: Failed to copy app.py and requirements.txt"
    exit 1
fi

# Create empty __init__.py files for Python packages
echo "📦 Setting up Python package structure..."
if ! ssh -i $KEY_PATH $SSH_OPTS $EC2_USER@$EC2_HOST "
    set -x  # Enable command tracing
    touch $REMOTE_DIR/api/__init__.py
    touch $REMOTE_DIR/api/services/__init__.py
    touch $REMOTE_DIR/api/scripts/__init__.py
"; then
    echo "❌ Error: Failed to create Python package structure"
    exit 1
fi

# Set up Python environment and install dependencies
echo "🐍 Setting up Python environment..."
if ! ssh -i $KEY_PATH $SSH_OPTS $EC2_USER@$EC2_HOST "
    set -ex  # Exit on error and enable command tracing
    
    echo '🧹 Cleaning up previous Python environment...'
    rm -rf ~/venv
    
    echo '📦 Creating new virtual environment...'
    python3 -m venv ~/venv
    source ~/venv/bin/activate
    
    echo '📦 Installing dependencies...'
    cd $REMOTE_DIR/api
    
    # Upgrade pip and install build tools
    pip install --upgrade pip setuptools wheel
    
    # Install core dependencies using pre-built wheels where possible
    pip install --only-binary :all: 'numpy<2.0'
    pip install --only-binary :all: 'torch==2.2.0+cpu' -f https://download.pytorch.org/whl/cpu/torch_stable.html
    pip install --only-binary :all: 'tokenizers==0.15.2'
    pip install --only-binary :all: 'transformers==4.38.1'
    pip install --only-binary :all: 'sentence-transformers==2.5.1'
    
    # Pre-download the model to avoid timeout issues
    echo '📦 Pre-downloading sentence transformer model...'
    python -c \"from sentence_transformers import SentenceTransformer; SentenceTransformer(\\\"flax-sentence-embeddings/st-codesearch-distilroberta-base\\\")\"
    
    # Install remaining requirements but skip the ML packages we already installed
    pip install -r <(grep -v 'torch\|transformers\|sentence-transformers\|numpy\|tokenizers' requirements.txt)
    
    echo '🔧 Verifying environment...'
    if [ ! -f .env ]; then
        echo '❌ Error: .env file not found in api directory!'
        exit 1
    fi
    
    echo '📋 Environment contents:'
    ls -la
    echo '📋 Services directory contents:'
    ls -la services/
    
    echo '🧪 Testing environment setup...'
    python -c 'import torch; import numpy; import pinecone; print(\"NumPy version:\", numpy.__version__); print(\"Torch version:\", torch.__version__); print(\"Pinecone package version:\", pinecone.__version__)'
    
    echo '🔧 Testing DNS resolution...'
    source .env
    PINECONE_HOST=\"controller.\${PINECONE_ENVIRONMENT}.pinecone.io\"
    echo \"Testing connection to \${PINECONE_HOST}...\"
    if ! ping -c 1 \${PINECONE_HOST} &> /dev/null; then
        echo \"❌ Error: Cannot resolve Pinecone host. Adding to /etc/hosts...\"
        echo \"3.33.120.147 \${PINECONE_HOST}\" | sudo tee -a /etc/hosts
    fi
    
    echo '🧪 Running test on Tally repositories...'
    PYTHONPATH=$REMOTE_DIR/api python scripts/process_sherlock_repos.py 2024-11-tally 2024-11-tally-judging
"; then
    echo "❌ Error: Failed to set up Python environment and run tests"
    exit 1
fi

echo "✅ Deployment and test completed!"
echo "📝 To check logs, run: ./scripts/check_logs.sh" 