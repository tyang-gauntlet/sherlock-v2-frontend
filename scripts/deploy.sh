#!/bin/bash

# Exit on error
set -e

echo "Starting deployment process..."

# Build frontend
echo "Building frontend..."
npm install
npm run build

# Copy frontend build to Nginx directory
sudo rm -rf /var/www/html/*
sudo cp -r build/* /var/www/html/

# Deploy backend using Docker Compose
echo "Deploying backend..."
cd api
docker-compose down || true
docker-compose up --build -d

echo "Restarting Nginx..."
sudo systemctl restart nginx

echo "Deployment completed successfully!"
echo "Your application should now be accessible at http://your-ec2-ip" 