#!/bin/bash

echo "🔧 Setting up Python environment for M1/M2 Mac..."

# Check if Python 3.11 is installed (more stable than 3.12 for all packages)
if ! command -v python3.11 &> /dev/null; then
    echo "❌ Python 3.11 is required but not found."
    echo "Please install it using: brew install python@3.11"
    exit 1
fi

# Create and activate virtual environment
echo "📦 Creating virtual environment..."
python3.11 -m venv venv
source venv/bin/activate

# Upgrade pip and install build tools
echo "🔄 Upgrading pip and installing build tools..."
pip install --upgrade pip setuptools wheel

# Install core dependencies with proper architecture support
echo "📚 Installing core dependencies..."
pip install --no-cache-dir \
    'numpy<2.0' \
    'torch==2.2.0' \
    'transformers==4.38.1' \
    'sentence-transformers==2.5.1' \
    'pinecone-client==3.0.2' \
    'PyGithub==2.1.1' \
    'GitPython==3.1.41' \
    'flask==2.3.3' \
    'flask-cors==4.0.0' \
    'python-dotenv==1.0.0' \
    'requests==2.31.0' \
    'tqdm==4.66.2' \
    'cryptography==42.0.5'

# Verify the installation
echo "✅ Verifying installation..."
python3.11 -c "
import torch
import transformers
import sentence_transformers
import pinecone
import github
import git
import flask
import cryptography

print('All core packages imported successfully!')
"

if [ $? -eq 0 ]; then
    echo "✨ Setup completed successfully!"
    echo "To activate the environment, run: source venv/bin/activate"
else
    echo "❌ Setup failed. Please check the error messages above."
    exit 1
fi 