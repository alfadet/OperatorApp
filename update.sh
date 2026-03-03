#!/bin/bash
cd /var/www/OperatorApp
git pull origin main
docker build -t operatorapp . -q
docker stop operatorapp
docker rm operatorapp
docker run -d --name operatorapp -p 8081:80 --restart always operatorapp
