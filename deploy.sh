#!/bin/bash

# Production deployment script for InstaBulk Pro

echo "🚀 Starting deployment..."

# Update system packages
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and pip
sudo apt-get install python3 python3-pip python3-venv nginx supervisor -y

# Install Chrome for Selenium
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt-get update
sudo apt-get install google-chrome-stable -y

# Create application directory
sudo mkdir -p /var/www/instabulk
sudo chown $USER:$USER /var/www/instabulk
cd /var/www/instabulk

# Clone repository (replace with your repo)
git clone https://github.com/yourusername/instabulk-pro.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p uploads logs

# Set up environment variables
cp .env.example .env
echo "⚠️  Please edit .env file with your actual configuration"

# Set up Nginx configuration
sudo tee /etc/nginx/sites-available/instabulk << EOF
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /static {
        alias /var/www/instabulk/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    client_max_body_size 20M;
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/instabulk /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

# Set up Supervisor for process management
sudo tee /etc/supervisor/conf.d/instabulk.conf << EOF
[program:instabulk]
command=/var/www/instabulk/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
directory=/var/www/instabulk
user=$USER
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/www/instabulk/logs/app.log
environment=FLASK_ENV=production
EOF

# Start services
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start instabulk

# Set up SSL with Let's Encrypt (optional)
echo "🔒 Setting up SSL..."
sudo apt-get install certbot python3-certbot-nginx -y
echo "Run: sudo certbot --nginx -d your-domain.com -d www.your-domain.com"

echo "✅ Deployment complete!"
echo "📝 Don't forget to:"
echo "   1. Edit /var/www/instabulk/.env with your configuration"
echo "   2. Set up SSL certificate"
echo "   3. Configure your domain DNS"
echo "   4. Set up Lemon Squeezy webhooks"
