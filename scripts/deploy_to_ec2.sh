#!/bin/bash

# Configuration
EC2_HOST="ec2-52-90-169-241.compute-1.amazonaws.com"
EC2_USER="ec2-user"
KEY_PATH="../smartsmart.pem"
REMOTE_APP_DIR="/home/ec2-user/sherlock-v2-frontend"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

echo "🚀 Starting deployment to EC2..."

# Create the application directory on EC2
echo "📁 Creating application directory..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "mkdir -p $REMOTE_APP_DIR"

# Copy the entire project to EC2
echo "📦 Copying project files to EC2..."
scp -i $KEY_PATH -r \
    ./* \
    .env \
    $EC2_USER@$EC2_HOST:$REMOTE_APP_DIR/

# Copy deployment scripts
echo "📜 Copying deployment scripts..."
scp -i $KEY_PATH -r scripts/ $EC2_USER@$EC2_HOST:~/

# Make scripts executable
echo "🔧 Setting up scripts..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "chmod +x ~/scripts/*.sh"

# Run setup script if not already done
echo "⚙️ Running setup script..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "~/scripts/setup_ec2.sh"

# Copy Nginx configuration
echo "🔧 Configuring Nginx..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "sudo cp ~/scripts/nginx.conf /etc/nginx/conf.d/app.conf && sudo systemctl restart nginx"

# Run deployment script
echo "🚀 Deploying application..."
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "cd $REMOTE_APP_DIR && ~/scripts/deploy.sh"

echo "✅ Deployment completed!"
echo "🌍 Your application should now be accessible at http://$EC2_HOST"
echo "📝 To check logs, run: ssh -i $KEY_PATH $EC2_USER@$EC2_HOST 'cd $REMOTE_APP_DIR && docker-compose logs -f'" 