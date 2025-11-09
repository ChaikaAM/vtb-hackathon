#!/bin/bash

set -e

SERVER="seagull@158.160.7.63"
DOMAIN="vtb.seag.pro"

echo "🔐 Setting up SSL certificate for $DOMAIN..."

# Create temporary HTTP-only nginx config
cat > /tmp/nginx-http-only.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 200 "SSL setup in progress...";
        add_header Content-Type text/plain;
    }
}
EOF

# Deploy HTTP-only config
scp /tmp/nginx-http-only.conf $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/nginx-http-only.conf /etc/nginx/sites-available/$DOMAIN && \
             sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN && \
             sudo nginx -t && \
             sudo systemctl reload nginx"

# Obtain SSL certificate
echo "📜 Obtaining SSL certificate from Let's Encrypt..."
ssh $SERVER "sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect" || echo "Certificate may already exist"

echo "✅ SSL certificate setup completed!"
echo "🔐 Certificate installed for $DOMAIN"

