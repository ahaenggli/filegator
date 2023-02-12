FROM php:7-apache-buster as composerbuild
RUN mkdir -p /var/www
WORKDIR /var/www

# Install git
RUN apt-get update > /dev/null && \
    apt-get install -y git zip unzip

RUN git clone https://github.com/ahaenggli/filegator.git && \
    cd filegator && \
    git fetch --all && \
    git checkout features/shared-links && \ 
    git pull 

WORKDIR /var/www/filegator

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
RUN composer install --ignore-platform-reqs

FROM node:14-buster as npmbuild
RUN mkdir -p /app/filegator
WORKDIR /app/filegator

COPY --from=composerbuild /var/www/filegator /app/filegator 

RUN apt-get update && apt-get upgrade -y && apt-get install -y python2
RUN apt-get install -y curl git wget unzip zip

RUN npm install
RUN npm update  & npm audit fix

# COPY ./filegator/frontend /app/filegator/frontend
# COPY ./filegator/.eslintrc.js /app/filegator/.eslintrc.js

RUN apt-get install -y dos2unix 
RUN find . -type f -name '*.vue' -exec dos2unix {} +
RUN find . -type f -name '*.js' -exec dos2unix {} +
# RUN find . -type f -name '*.js'  -exec sed -i 's/\r\n$/\n$/' {} +

RUN npm run build --fix
RUN npm run build --fix

# re install as production, so less packages are downloaded
ENV NODE_ENV="production"
RUN rm -rf node_modules package-lock.json && npm install && npm audit fix


######## hier ############
FROM php:8-fpm-alpine

RUN apk update && apk upgrade

RUN apk --update \
    add lighttpd && \
    rm -rf /var/cache/apk/*

RUN apk add --no-cache libzip-dev ldb-dev libldap openldap-dev   
RUN docker-php-ext-install zip \
    && docker-php-ext-install ldap \
    && docker-php-ext-install session 
RUN apk add --no-cache php-sqlite3 
RUN docker-php-ext-install posix 
RUN docker-php-ext-enable zip \
    && docker-php-ext-enable ldap \
    && docker-php-ext-enable session 

RUN apk add --no-cache php-opcache 

# Use the default production configuration
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
RUN echo "cgi.fix_pathinfo=1" >> "$PHP_INI_DIR/php.ini"

RUN echo "zend_extension=opcache.so" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.enable=1" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.memory_consumption=128" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.interned_strings_buffer=8" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.max_accelerated_files=4000" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.revalidate_freq=60" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.fast_shutdown=1" >> "$PHP_INI_DIR/php.ini"
RUN echo "opcache.enable_cli=1" >> "$PHP_INI_DIR/php.ini"


RUN sed -i 's/^max_file_uploads = .*/max_file_uploads = 100/' $PHP_INI_DIR/php.ini
RUN sed -i 's/^memory_limit = .*/memory_limit = 1512M/' $PHP_INI_DIR/php.ini
RUN sed -i 's/^post_max_size = .*/post_max_size = 1500M/' $PHP_INI_DIR/php.ini
RUN sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 1500M/' $PHP_INI_DIR/php.ini

#RUN mkdir /var/run/lighttpd
#RUN touch /var/run/lighttpd/php-fastcgi.socket
#RUN chown -R lighttpd:lighttpd /var/run/lighttpd


#ADD 15-fastcgi-php.conf /etc/lighttpd/conf-available/15-fastcgi-php.conf
COPY --from=npmbuild /app/filegator /var/www/filegator

ADD lighttpd.conf /etc/lighttpd/lighttpd.conf

RUN mkdir -p /run/lighttpd/ && \
    chown www-data. /run/lighttpd/ && \ 
    chown -R www-data. /var/www/

RUN mkdir -p /var/log/lighttpd/ 

EXPOSE 80

VOLUME /var/www/filegator/repository
VOLUME /var/www/filegator/private
VOLUME /var/www/filegator/configuration.php

CMD php-fpm -D && lighttpd -D -f /etc/lighttpd/lighttpd.conf

### docker build -t ahaen/filegator-test:dev-l .
