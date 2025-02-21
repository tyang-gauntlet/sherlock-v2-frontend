#!/bin/bash

# Configuration
EC2_HOST="ec2-54-157-41-25.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

echo "🔧 Setting up supervisor configuration..."

# Create supervisor config
SUPERVISOR_CONFIG="[program:sherlock-api]
command=/home/ubuntu/venv/bin/gunicorn -w 4 -b 0.0.0.0:5001 --timeout 120 app:app
directory=/home/ubuntu/sherlock-v2-frontend/api
user=ubuntu
autostart=true
autorestart=true
stderr_logfile=/var/log/sherlock-api.err.log
stdout_logfile=/var/log/sherlock-api.out.log
environment=PYTHONPATH=\"/home/ubuntu/sherlock-v2-frontend/api\",PATH=\"/home/ubuntu/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",SOLC_VERSION=\"0.8.28\",SOLC=\"/usr/bin/solc\"
stopasgroup=true
killasgroup=true"

# Copy supervisor config and set up service
ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "
    # Install supervisor if not already installed
    sudo apt-get update
    sudo apt-get install -y supervisor

    # Create supervisor config
    echo '$SUPERVISOR_CONFIG' | sudo tee /etc/supervisor/conf.d/sherlock-api.conf

    # Create log files with proper permissions
    sudo touch /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log
    sudo chown ubuntu:ubuntu /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log
    sudo chmod 644 /var/log/sherlock-api.out.log /var/log/sherlock-api.err.log /var/log/sherlock-api.analysis.log

    # Create and set permissions for uploads directory
    mkdir -p $REMOTE_DIR/api/uploads
    chmod 755 $REMOTE_DIR/api/uploads

    # Make sure supervisor is running
    sudo service supervisor start

    # Reload supervisor
    sudo supervisorctl reread
    sudo supervisorctl update
    sudo supervisorctl restart sherlock-api

    # Show status
    sudo supervisorctl status sherlock-api
"

echo "✅ Supervisor configuration completed!" 