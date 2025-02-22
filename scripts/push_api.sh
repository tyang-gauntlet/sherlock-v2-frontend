#!/bin/bash

set -e  # Exit on any error

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"
API_PORT="5001"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Pushing API changes to EC2..."

# Clean up local __pycache__ directories
echo "🧹 Cleaning up Python cache files..."
find ./api -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Create remote directory structure
echo "📁 Creating remote directories..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    mkdir -p $REMOTE_DIR/api/uploads
    mkdir -p $REMOTE_DIR/api/services
"

# Copy project files to EC2
echo "📦 Copying project files..."
rsync -av --exclude '__pycache__' \
         --exclude '*.pyc' \
         --exclude 'analysis.log' \
         -e "ssh -i $KEY_PATH" \
         ../api/ $EC2_USER@$EC2_HOST:$REMOTE_DIR/api/

# Set up proper permissions and restart service
echo "🔧 Setting up permissions and restarting service..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    # Set proper permissions
    sudo chown -R ubuntu:ubuntu $REMOTE_DIR
    sudo chmod -R 755 $REMOTE_DIR
    sudo chmod 777 $REMOTE_DIR/api/uploads

    # Create and set permissions for log files
    sudo touch /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log
    sudo chown ubuntu:ubuntu /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log
    sudo chmod 644 /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log

    # Install dependencies
    echo '🐍 Installing Python packages...'
    source ~/venv/bin/activate
    pip install -r $REMOTE_DIR/api/requirements.txt
    pip install slither-analyzer 'crytic-compile>=0.3.1' solc-select

    # Restart the service
    sudo supervisorctl reread
    sudo supervisorctl update
    sudo supervisorctl restart sherlock-api

    # Wait for service to start
    sleep 2

    # Check service status
    sudo supervisorctl status sherlock-api
"

echo "✅ API changes deployed!"
echo "🌍 Test the API with: curl http://$EC2_HOST:$API_PORT/health"
echo "📝 View logs with: ssh -i $KEY_PATH $EC2_USER@$EC2_HOST 'sudo tail -f /var/log/sherlock-api.out.log'"
