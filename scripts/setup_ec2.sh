#!/bin/bash

# Configuration
EC2_HOST="ec2-52-90-169-241.compute-1.amazonaws.com"
EC2_USER="ec2-user"
KEY_PATH="../smartsmart.pem"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Running setup on EC2..."

# Run setup commands on EC2
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST '
    set -e  # Exit on any error
    
    echo "📦 Updating system packages..."
    sudo dnf update -y
    
    echo "📦 Installing Node.js and npm..."
    sudo dnf install -y nodejs npm
    
    echo "🐳 Installing Docker..."
    sudo dnf install -y docker
    
    echo "🐳 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    
    echo "👤 Configuring Docker permissions..."
    sudo usermod -aG docker $USER
    
    echo "▶️ Starting Docker service..."
    sudo systemctl start docker
    sudo systemctl enable docker
'

echo "✅ Setup completed successfully!"
echo "⚠️  Please wait a moment for changes to take effect..."
echo "🚀 You can now run ./scripts/push_api.sh to deploy your API" 