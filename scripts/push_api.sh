#!/bin/bash

set -e  # Exit on any error

# Configuration
EC2_HOST="ec2-52-90-169-241.compute-1.amazonaws.com"
EC2_USER="ec2-user"
KEY_PATH="../smartsmart.pem"
REMOTE_DIR="/home/ec2-user/sherlock-v2-frontend"
API_PORT="5001"  # The port specified in docker-compose.yml

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Pushing API changes to EC2..."

# Check if docker is running on remote
echo "🔍 Checking Docker status..."
if ! ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "sudo systemctl is-active docker"; then
    echo "⚠️  Docker is not running. Starting Docker..."
    ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "sudo systemctl start docker"
fi

# Create remote directory structure and set permissions
echo "📁 Setting up directories..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    sudo rm -rf $REMOTE_DIR
    mkdir -p $REMOTE_DIR
    sudo chown -R $EC2_USER:$EC2_USER $REMOTE_DIR
"

# Clean up local __pycache__ directories
echo "🧹 Cleaning up Python cache files..."
find ./api -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Copy project files to EC2
echo "📦 Copying project files..."
scp -i $KEY_PATH docker-compose.yml $EC2_USER@$EC2_HOST:$REMOTE_DIR/
rsync -av --exclude '__pycache__' \
         --exclude '*.pyc' \
         -e "ssh -i $KEY_PATH" \
         ./api/ $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/

# Restart Docker containers
echo "🔄 Restarting Docker containers..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "cd $REMOTE_DIR && docker-compose down && docker-compose up --build -d"

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 5

# Verify the container is running and get the actual port
echo "🔍 Verifying deployment..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "docker ps | grep solidity-analyzer"

echo "✅ API changes deployed!"
echo "🌍 Test the API with: curl http://$EC2_HOST:$API_PORT/health"
echo "📝 View logs with: ssh -i $KEY_PATH $EC2_USER@$EC2_HOST 'cd $REMOTE_DIR && docker-compose logs -f'"

# Print reminder about security group
echo "⚠️  Remember to ensure port $API_PORT is open in your EC2 security group"
echo "   You can do this in the AWS Console under EC2 -> Security Groups" 