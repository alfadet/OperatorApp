#!/bin/bash
cd /var/www/OperatorApp
GIT_TERMINAL_PROMPT=0 git -c credential.helper= pull https://github.com/alfadet/OperatorApp.git main | grep -q "Already up to date." && exit 0
docker build -t operatorapp . -q
docker stop operatorapp
docker rm operatorapp
docker run -d --name operatorapp -p 8081:80 --restart always operatorapp
