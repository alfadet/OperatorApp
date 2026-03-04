#!/bin/bash
cd /var/www/OperatorApp
GIT_TERMINAL_PROMPT=0 git -c credential.helper= pull https://github.com/alfadet/OperatorApp.git main | grep -q "Already up to date." && exit 0
docker-compose down
docker-compose build --no-cache
docker-compose up -d
