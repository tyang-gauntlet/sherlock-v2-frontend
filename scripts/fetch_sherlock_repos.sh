#!/bin/bash

set -e  # Exit on any error

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ec2-user"
KEY_PATH="../smartsmart2.pem"
REMOTE_DIR="/home/ec2-user/sherlock-v2-frontend"

# Get credentials from .env file
GITHUB_TOKEN=$(grep GITHUB_TOKEN .env | cut -d '=' -f2)
PINECONE_API_KEY=$(grep PINECONE_API_KEY .env | cut -d '=' -f2)
PINECONE_ENVIRONMENT=$(grep PINECONE_ENVIRONMENT .env | cut -d '=' -f2)

if [ -z "$GITHUB_TOKEN" ] || [ -z "$PINECONE_API_KEY" ] || [ -z "$PINECONE_ENVIRONMENT" ]; then
    echo "❌ Error: Missing required credentials in .env file"
    exit 1
fi

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Starting Sherlock repository processing..."

# Install system dependencies
echo "📦 Installing system dependencies..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    sudo yum update -y
    sudo yum install -y git python3-pip python3-devel
"

# Create necessary directories
echo "📁 Setting up directories..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    mkdir -p $REMOTE_DIR/api/services
    sudo chown -R $EC2_USER:$EC2_USER $REMOTE_DIR
"

# Copy the Python scripts and requirements
echo "📦 Copying scripts..."
scp -i $KEY_PATH api/fetch_sherlock_repos.py $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/
scp -i $KEY_PATH api/services/github_repo_manager.py $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/services/
scp -i $KEY_PATH api/services/embedding_processor.py $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/services/
scp -i $KEY_PATH api/requirements.txt $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/

# Create .env file on EC2
echo "🔐 Setting up environment variables..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    echo \"GITHUB_TOKEN=$GITHUB_TOKEN\" > $REMOTE_DIR/api/.env
    echo \"PINECONE_API_KEY=$PINECONE_API_KEY\" >> $REMOTE_DIR/api/.env
    echo \"PINECONE_ENVIRONMENT=$PINECONE_ENVIRONMENT\" >> $REMOTE_DIR/api/.env
"

# Set up Python environment and run the processor
echo "🐍 Setting up Python environment and running processor..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    cd $REMOTE_DIR/api
    python3 -m venv venv
    source venv/bin/activate
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    export GIT_PYTHON_REFRESH=quiet
    python fetch_sherlock_repos.py
"

echo "✅ Repository processing completed!"
echo "📊 Embeddings have been stored in Pinecone"
echo "🔍 You can now query the embeddings using the Pinecone console or API" 