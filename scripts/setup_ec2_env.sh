#!/bin/bash

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

echo "🔧 Setting up Python environment on EC2..."

# Set up Python environment and install dependencies
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
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
    
    # Install Flask and related packages
    pip install 'flask==2.3.3' 'flask-cors==4.0.0'
    
    # Install gunicorn
    pip install 'gunicorn>=22.0.0'
    
    # Install other required packages
    pip install 'python-dotenv==1.0.0' 'requests==2.31.0' 'pinecone-client==3.0.2' 'PyGithub==2.1.1' 'GitPython==3.1.41' 'openai==0.28.1'
    
    # Install solc and solc-select
    echo '📦 Installing solc and solc-select...'
    sudo add-apt-repository -y ppa:ethereum/ethereum
    sudo apt-get update
    sudo apt-get install -y solc
    pip install solc-select
    
    # Install slither
    echo '📦 Installing slither...'
    pip install slither-analyzer
    
    # Pre-download the model to avoid timeout issues
    echo '📦 Pre-downloading sentence transformer model...'
    python -c \"from sentence_transformers import SentenceTransformer; SentenceTransformer('flax-sentence-embeddings/st-codesearch-distilroberta-base')\"
    
    echo '🔧 Verifying environment...'
    python -c 'import flask, torch, numpy, pinecone, transformers, sentence_transformers, gunicorn; print(\"✅ All core packages imported successfully\")'
    
    # Create log file with proper permissions
    sudo touch /var/log/sherlock-api.analysis.log
    sudo chown ubuntu:ubuntu /var/log/sherlock-api.analysis.log
    sudo chmod 644 /var/log/sherlock-api.analysis.log
"

echo "✅ Python environment setup completed!" 