FROM nginx:alpine
COPY index.html /usr/share/nginx/html/
COPY libs/ /usr/share/nginx/html/libs/
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
