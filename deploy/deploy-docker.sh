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
DEPLOY_DIR="/opt/api-security-analyzer"

echo "🚀 Starting Docker deployment to $SERVER..."

# Create deployment directory on server
echo "📁 Creating deployment directory..."
ssh $SERVER "sudo mkdir -p $DEPLOY_DIR && sudo chown -R seagull:seagull $DEPLOY_DIR"

# Copy entire project to server (excluding node_modules and target)
echo "📤 Copying project files to server..."
rsync -av --exclude='node_modules' \
          --exclude='target' \
          --exclude='build' \
          --exclude='.git' \
          --exclude='*.log' \
          ./ $SERVER:$DEPLOY_DIR/

# Build and start containers on server
echo "🐳 Building Docker images on server..."
ssh $SERVER << 'EOF'
cd /opt/api-security-analyzer

# Stop existing containers
echo "Stopping existing containers..."
docker compose -f deploy/docker-compose.yml down || true

# Build and start services
echo "Building and starting services..."
docker compose -f deploy/docker-compose.yml up -d --build

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 30

# Check status
echo "Checking container status..."
docker compose -f deploy/docker-compose.yml ps

# Check backend health
echo "Checking backend health..."
for i in {1..10}; do
    if curl -f http://localhost:8080/api/analysis/health 2>/dev/null; then
        echo "✅ Backend is healthy!"
        break
    fi
    echo "Waiting for backend... ($i/10)"
    sleep 5
done

echo "✅ Docker containers started successfully!"
EOF

# Configure Nginx on host
echo "⚙️ Configuring Nginx..."
cat > /tmp/nginx-docker.conf << EOF
upstream backend {
    server localhost:8080;
}

upstream frontend {
    server localhost:3000;
}

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Backend API
    location /api/ {
        proxy_pass http://backend/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts for long-running analysis
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # Frontend
    location / {
        proxy_pass http://frontend/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript application/json;

    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
}
EOF

scp /tmp/nginx-docker.conf $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/nginx-docker.conf /etc/nginx/sites-available/$DOMAIN && \
             sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN && \
             sudo nginx -t && \
             sudo systemctl reload nginx"

echo ""
echo "✅ Deployment completed successfully!"
echo ""
echo "🌐 URLs:"
echo "  Frontend: https://$DOMAIN"
echo "  Backend API: https://$DOMAIN/api"
echo "  Health Check: https://$DOMAIN/api/analysis/health"
echo ""
echo "📊 Check status:"
echo "  ssh $SERVER 'cd $DEPLOY_DIR && docker compose -f deploy/docker-compose.yml ps'"
echo "  ssh $SERVER 'cd $DEPLOY_DIR && docker compose -f deploy/docker-compose.yml logs -f'"
echo ""
echo "🔄 Restart services:"
echo "  ssh $SERVER 'cd $DEPLOY_DIR && docker compose -f deploy/docker-compose.yml restart'"
echo ""

