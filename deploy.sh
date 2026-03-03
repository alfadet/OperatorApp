#!/bin/bash
# Script di deploy per VPS Hostinger
# Esegui come root: bash deploy.sh

set -e

APP_DIR="/var/www/operatorapp"
DOMAIN="tuodominio.com"

echo "=== Deploy OperatorApp su VPS ==="

# 1. Installa nginx se non presente
if ! command -v nginx &> /dev/null; then
    echo "[1/5] Installo nginx..."
    apt update && apt install -y nginx
else
    echo "[1/5] Nginx gia installato"
fi

# 2. Installa certbot per SSL
if ! command -v certbot &> /dev/null; then
    echo "[2/5] Installo certbot..."
    apt install -y certbot python3-certbot-nginx
else
    echo "[2/5] Certbot gia installato"
fi

# 3. Copia i file dell'app
echo "[3/5] Copio i file dell'app..."
mkdir -p $APP_DIR
cp -r ./* $APP_DIR/
chown -R www-data:www-data $APP_DIR
chmod -R 755 $APP_DIR

# 4. Configura nginx
echo "[4/5] Configuro nginx..."
cp nginx/operatorapp.conf /etc/nginx/sites-available/operatorapp
ln -sf /etc/nginx/sites-available/operatorapp /etc/nginx/sites-enabled/operatorapp
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# 5. SSL con Let's Encrypt
echo "[5/5] Configuro SSL..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m tua@email.com

echo ""
echo "=== Deploy completato! ==="
echo "App disponibile su: https://$DOMAIN"
