#!/bin/bash

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Running setup on EC2..."

# Run setup commands on EC2
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    set -e  # Exit on any error
    
    echo '🧹 Cleaning up previous installation...'
    rm -rf ~/sherlock-v2-frontend
    rm -rf ~/.local/lib/python*
    rm -rf ~/venv
    
    echo '📦 Updating system packages...'
    sudo apt-get update -y
    sudo apt-get install -y python3-full python3-pip python3-venv supervisor solc

    echo '🔧 Creating virtual environment...'
    python3 -m venv ~/venv
    source ~/venv/bin/activate

    echo '🐍 Installing Python packages...'
    pip install --upgrade pip
    pip install -r $REMOTE_DIR/api/requirements.txt
    pip install slither-analyzer 'crytic-compile>=0.3.1' solc-select

    echo '🔧 Setting up Solidity compiler...'
    solc-select install 0.8.28
    solc-select use 0.8.28

    echo '📁 Creating application directory...'
    mkdir -p ~/sherlock-v2-frontend/api/uploads
    chmod 777 ~/sherlock-v2-frontend/api/uploads

    echo '📝 Setting up supervisor configuration...'
    sudo tee /etc/supervisor/conf.d/sherlock-api.conf << EOL
[program:sherlock-api]
directory=/home/ubuntu/sherlock-v2-frontend/api
command=/home/ubuntu/venv/bin/gunicorn --bind 0.0.0.0:5001 --log-level debug --capture-output --enable-stdio-inheritance app:app
user=ubuntu
autostart=true
autorestart=true
environment=PYTHONUNBUFFERED=1
stdout_logfile=/var/log/sherlock-api.out.log
stderr_logfile=/var/log/sherlock-api.err.log
EOL

    echo '📋 Creating log files...'
    sudo touch /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log
    sudo chown ubuntu:ubuntu /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log

    echo '🔄 Reloading supervisor...'
    sudo supervisorctl reread
    sudo supervisorctl update

    echo '✨ Testing Slither installation...'
    slither --version
"

echo "✅ Setup completed successfully!"
echo "⚠️  Please wait a moment for changes to take effect..."
echo "🚀 You can now run ./scripts/push_api.sh to deploy your API" 