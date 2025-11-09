#!/bin/bash

set -e

SERVER="seagull@158.160.7.63"

echo "🔧 Setting up server: $SERVER"

# Install nginx if not installed
echo "📦 Installing nginx..."
ssh $SERVER "command -v nginx >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y nginx)"

# Install certbot if not installed
echo "🔐 Installing certbot..."
ssh $SERVER "command -v certbot >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y certbot python3-certbot-nginx)"

# Ensure nginx is running
echo "🔄 Starting nginx..."
ssh $SERVER "sudo systemctl enable nginx && sudo systemctl start nginx"

echo "✅ Server setup completed!"

