#!/bin/bash

set -e

SERVER="seagull@158.160.7.63"

echo "🔧 Setting up server for Docker deployment..."

ssh $SERVER << 'EOF'
# Update system
echo "📦 Updating system..."
sudo apt-get update

# Install Docker if not installed
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
else
    echo "✅ Docker already installed"
fi

# Docker Compose is now built into Docker
# Check if docker compose works
if docker compose version &> /dev/null; then
    echo "✅ Docker Compose (built-in) available"
elif command -v docker-compose &> /dev/null; then
    echo "✅ Docker Compose (standalone) installed"
else
    echo "⚠️ Docker Compose not found, but will use 'docker compose' command"
fi

# Install nginx if not installed
if ! command -v nginx &> /dev/null; then
    echo "🌐 Installing Nginx..."
    sudo apt-get install -y nginx
else
    echo "✅ Nginx already installed"
fi

# Install certbot if not installed
if ! command -v certbot &> /dev/null; then
    echo "🔐 Installing Certbot..."
    sudo apt-get install -y certbot python3-certbot-nginx
else
    echo "✅ Certbot already installed"
fi

# Create deployment directory
echo "📁 Creating deployment directory..."
sudo mkdir -p /opt/api-security-analyzer
sudo chown -R seagull:seagull /opt/api-security-analyzer

# Enable Docker service
echo "⚙️ Enabling Docker service..."
sudo systemctl enable docker
sudo systemctl start docker

echo "✅ Server setup completed!"
echo ""
echo "📊 Installed versions:"
docker --version
docker compose version 2>/dev/null || echo "Docker Compose: using built-in"
nginx -v
certbot --version
EOF

echo ""
echo "✅ Server setup completed!"
echo "🚀 Ready for deployment. Run: ./deploy/deploy-docker.sh"

