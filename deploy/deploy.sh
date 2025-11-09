#!/bin/bash

set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Get the project root (parent of deploy directory)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Change to project root
cd "$PROJECT_ROOT"

SERVER="seagull@158.160.7.63"
DOMAIN="vtb.seag.pro"
APP_DIR="/var/www/vtb.seag.pro"
NGINX_CONF="/etc/nginx/sites-available/vtb.seag.pro"
NGINX_ENABLED="/etc/nginx/sites-enabled/vtb.seag.pro"

echo "🚀 Starting deployment to $SERVER..."

# Build React app locally
echo "📦 Building React app..."
cd frontend
npm install
npm run build
cd ..

# Create necessary directories on server
echo "📁 Creating directories on server..."
ssh $SERVER "sudo mkdir -p $APP_DIR && sudo mkdir -p /var/www/html"

# Copy built files to server
echo "📤 Copying files to server..."
scp -r frontend/build/* $SERVER:/tmp/vtb-build/
ssh $SERVER "sudo rm -rf $APP_DIR/* && sudo cp -r /tmp/vtb-build/* $APP_DIR/ && sudo chown -R www-data:www-data $APP_DIR && rm -rf /tmp/vtb-build"

# Copy nginx configuration (first HTTP only for certbot)
echo "⚙️  Configuring nginx..."
scp deploy/nginx.conf.http $SERVER:/tmp/nginx-vtb.conf
ssh $SERVER "sudo cp /tmp/nginx-vtb.conf $NGINX_CONF && sudo rm /tmp/nginx-vtb.conf"

# Create symlink if it doesn't exist
ssh $SERVER "sudo ln -sf $NGINX_CONF $NGINX_ENABLED || true"

# Test nginx configuration
echo "🔍 Testing nginx configuration..."
ssh $SERVER "sudo nginx -t"

# Reload nginx with HTTP config
echo "🔄 Reloading nginx with HTTP config..."
ssh $SERVER "sudo systemctl reload nginx"

# Install certbot if not installed
echo "🔐 Setting up SSL certificate..."
ssh $SERVER "command -v certbot >/dev/null 2>&1 || sudo apt-get update && sudo apt-get install -y certbot python3-certbot-nginx"

# Obtain SSL certificate
echo "📜 Obtaining SSL certificate from Let's Encrypt..."
CERT_RESULT=$(ssh $SERVER "sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect 2>&1" || echo "certbot_failed")
if [[ "$CERT_RESULT" == *"certbot_failed"* ]] || [[ "$CERT_RESULT" == *"already exists"* ]]; then
    echo "⚠️  Certificate may already exist or domain not pointing to server. Continuing..."
else
    echo "✅ SSL certificate obtained successfully"
fi

# Now copy full HTTPS configuration
echo "🔒 Applying HTTPS configuration..."
scp deploy/nginx.conf $SERVER:/tmp/nginx-vtb-https.conf
ssh $SERVER "sudo cp /tmp/nginx-vtb-https.conf $NGINX_CONF && sudo rm /tmp/nginx-vtb-https.conf"

# Test nginx configuration again
echo "🔍 Testing HTTPS nginx configuration..."
ssh $SERVER "sudo nginx -t"

# Reload nginx with HTTPS config
echo "🔄 Reloading nginx with HTTPS config..."
ssh $SERVER "sudo systemctl reload nginx"

echo "✅ Deployment completed successfully!"
echo "🌐 Your site should be available at: https://$DOMAIN"

