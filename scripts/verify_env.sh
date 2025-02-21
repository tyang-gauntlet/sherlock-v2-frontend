#!/bin/bash

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

echo "🔍 Verifying environment setup..."

# Copy supervisor config and set up service
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    set -x  # Enable command tracing
    
    # Check if .env exists
    if [ ! -f $REMOTE_DIR/api/.env ]; then
        echo '❌ .env file missing in api directory'
        exit 1
    fi
    
    # Check directory structure
    echo '📁 Checking directory structure...'
    ls -la $REMOTE_DIR/api
    ls -la $REMOTE_DIR/api/services
    
    # Check Python environment
    echo '🐍 Checking Python environment...'
    source ~/venv/bin/activate
    which python
    python --version
    pip list | grep -E 'gunicorn|flask|torch|transformers'
    
    # Check supervisor configuration
    echo '🔧 Checking supervisor configuration...'
    sudo cat /etc/supervisor/conf.d/sherlock-api.conf
    
    # Check log files
    echo '📝 Checking log files...'
    ls -l /var/log/sherlock-api*
    
    # Try to start the service manually
    echo '🚀 Attempting to start service manually...'
    cd $REMOTE_DIR/api
    source ~/venv/bin/activate
    python -c 'import app; print(\"✅ App imports successfully\")'
    
    # Restart supervisor
    echo '🔄 Restarting supervisor...'
    sudo supervisorctl reread
    sudo supervisorctl update
    sudo supervisorctl restart sherlock-api
    sudo supervisorctl status sherlock-api
"

echo "✅ Environment verification completed!" 