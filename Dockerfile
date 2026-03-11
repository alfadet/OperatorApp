FROM nginx:alpine
COPY index.html /usr/share/nginx/html/
COPY libs/ /usr/share/nginx/html/libs/
COPY manifest.json /usr/share/nginx/html/
COPY sw.js /usr/share/nginx/html/
COPY OneSignalSDKWorker.js /usr/share/nginx/html/
COPY icon-192.png /usr/share/nginx/html/
COPY icon-512.png /usr/share/nginx/html/
COPY logo-alfa.png /usr/share/nginx/html/
COPY logo-operator.png /usr/share/nginx/html/
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
