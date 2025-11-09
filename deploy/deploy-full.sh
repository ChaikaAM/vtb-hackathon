#!/bin/bash

set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Get the project root (parent of deploy directory)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Change to project root
cd "$PROJECT_ROOT"

echo "🚀 Starting full deployment (Frontend + Backend)..."

SERVER="seagull@158.160.7.63"
DOMAIN="vtb.seag.pro"
FRONTEND_DIR="/var/www/vtb.seag.pro"
BACKEND_DIR="/var/www/vtb-backend"

# Build Backend
echo "📦 Building Backend..."
cd backend
./mvnw clean package -DskipTests
cd ..

# Build Frontend
echo "📦 Building Frontend..."
cd frontend
npm install
npm run build
cd ..

# Deploy Backend
echo "🚀 Deploying Backend..."
ssh $SERVER "sudo mkdir -p $BACKEND_DIR"
scp backend/target/api-security-analyzer-1.0.0.jar $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/api-security-analyzer-1.0.0.jar $BACKEND_DIR/app.jar"

# Create systemd service for backend
cat > /tmp/api-security-analyzer.service <<EOF
[Unit]
Description=API Security Analyzer Backend
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$BACKEND_DIR
ExecStart=/usr/bin/java -jar $BACKEND_DIR/app.jar
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=api-security-analyzer

[Install]
WantedBy=multi-user.target
EOF

scp /tmp/api-security-analyzer.service $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/api-security-analyzer.service /etc/systemd/system/ && \
             sudo systemctl daemon-reload && \
             sudo systemctl enable api-security-analyzer && \
             sudo systemctl restart api-security-analyzer"

# Deploy Frontend
echo "🚀 Deploying Frontend..."
scp -r frontend/build/* $SERVER:/tmp/vtb-build/
ssh $SERVER "sudo rm -rf $FRONTEND_DIR/* && \
             sudo cp -r /tmp/vtb-build/* $FRONTEND_DIR/ && \
             sudo chown -R www-data:www-data $FRONTEND_DIR && \
             rm -rf /tmp/vtb-build"

# Update nginx config with backend proxy
cat > /tmp/nginx-vtb-full.conf <<EOF
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

    # Frontend
    root $FRONTEND_DIR;
    index index.html;

    # Backend API proxy
    location /api/ {
        proxy_pass http://localhost:8080/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Frontend routes
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json;

    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
}
EOF

scp /tmp/nginx-vtb-full.conf $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/nginx-vtb-full.conf /etc/nginx/sites-available/$DOMAIN && \
             sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN && \
             sudo nginx -t && \
             sudo systemctl reload nginx"

echo "✅ Full deployment completed!"
echo "🌐 Frontend: https://$DOMAIN"
echo "🔌 Backend: https://$DOMAIN/api"
echo "📊 Health check: https://$DOMAIN/api/analysis/health"

