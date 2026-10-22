FROM php:8.3-apache-bullseye AS builder

RUN mkdir -p /var/www
WORKDIR /var/www


# Install git
RUN curl -sL https://deb.nodesource.com/setup_22.x | bash -
RUN apt-get update > /dev/null && \
    apt-get install -y git zip unzip

RUN apt-get update > /dev/null
RUN apt-get install -y git libzip-dev nodejs python2 libgtk2.0-0 libgtk-3-0 libgbm-dev libnotify-dev libgconf-2-4 libnss3 libxss1 libasound2 libxtst6 xauth xvfb

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN docker-php-ext-install zip
RUN docker-php-ext-enable zip

RUN git clone https://github.com/ahaenggli/filegator.git && \
    cd filegator && \
    git fetch --all && \
    git checkout features/shared-links && \ 
    git pull 

WORKDIR /var/www/filegator

RUN composer install
RUN composer require league/flysystem-sftp:^1.0 -W
RUN composer require league/flysystem-aws-s3-v3:^1.0 -W
RUN npm install

RUN apt-get install -y dos2unix 
# COPY ./filegator/frontend /app/filegator/frontend
# COPY ./filegator/.eslintrc.js /app/filegator/.eslintrc.js

RUN find . -type f -name '*.vue' -exec dos2unix {} +
RUN find . -type f -name '*.js' -exec dos2unix {} +


RUN npm run build
RUN vendor/bin/phpunit
RUN npm run lint
#RUN npm run test:e2e
RUN rm -rf node_modules frontend tests docs .git .github
RUN rm README.md couscous.yml repository/.gitignore babel.config.js cypress* .env* .eslint* .gitignore jest.* .php_cs* phpunit* postcss* vue*


######## hier ############
FROM php:8.3-fpm-alpine

# Runtime / build dependencies
RUN apk add --no-cache \
        lighttpd \
        libzip-dev \
        openldap-dev \
        sqlite-dev \
        php-sqlite3

# PHP extensions
RUN docker-php-ext-install zip
RUN docker-php-ext-install ldap
RUN docker-php-ext-install posix
RUN docker-php-ext-install opcache
RUN docker-php-ext-install pdo_sqlite

# Production PHP configuration
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

RUN { \
        echo "cgi.fix_pathinfo=1"; \
        echo "opcache.enable=1"; \
        echo "opcache.memory_consumption=128"; \
        echo "opcache.interned_strings_buffer=8"; \
        echo "opcache.max_accelerated_files=4000"; \
        echo "opcache.revalidate_freq=60"; \
        echo "opcache.enable_cli=1"; \
    } >> "$PHP_INI_DIR/php.ini"

RUN sed -i 's/^max_file_uploads = .*/max_file_uploads = 100/' "$PHP_INI_DIR/php.ini" \
    && sed -i 's/^memory_limit = .*/memory_limit = 1512M/' "$PHP_INI_DIR/php.ini" \
    && sed -i 's/^post_max_size = .*/post_max_size = 1500M/' "$PHP_INI_DIR/php.ini" \
    && sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 1500M/' "$PHP_INI_DIR/php.ini" \
    && sed -i 's/^max_execution_time = .*/max_execution_time = 3600/' "$PHP_INI_DIR/php.ini" \
    && sed -i 's/^max_input_time = .*/max_input_time = 300/' "$PHP_INI_DIR/php.ini"

# PHP-FPM pool
RUN set -eux; \
    { \
        echo '[www]'; \
        echo 'pm.max_children = 10'; \
        echo 'pm.start_servers = 4'; \
        echo 'pm.min_spare_servers = 2'; \
        echo 'pm.max_spare_servers = 6'; \
    } | tee "/usr/local/etc/php-fpm.d/zzz-pm.conf"

# Application
COPY --from=builder /var/www/filegator /var/www/filegator

COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY mime-types.conf /etc/lighttpd/mime-types.conf
COPY mod_fastcgi_fpm.conf /etc/lighttpd/mod_fastcgi_fpm.conf
COPY mod_fastcgi.conf /etc/lighttpd/mod_fastcgi.conf
COPY mod_cgi.conf /etc/lighttpd/mod_cgi.conf


RUN mkdir -p /run/lighttpd /var/log/lighttpd \
    && chown -R www-data:www-data /run/lighttpd /var/www/

EXPOSE 80

VOLUME /var/www/filegator/repository
VOLUME /var/www/filegator/private
VOLUME /var/www/filegator/configuration.php

CMD php-fpm -D && lighttpd -D -f /etc/lighttpd/lighttpd.conf

### podman build -t docker.io/ahaen/filegator-test:dev .
