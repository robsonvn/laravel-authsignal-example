FROM php:8.1-fpm

RUN apt-get update \
 && apt install -y \
    zlib1g-dev \
    libcurl4-openssl-dev \
    libpq-dev \
    libzip-dev \
  && docker-php-ext-configure opcache --enable-opcache \
  && docker-php-ext-install zip curl opcache pdo pdo_pgsql pgsql

RUN EXPECTED_CHECKSUM="$(php -r 'copy("https://composer.github.io/installer.sig", "php://stdout");')" \
 && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
 && ACTUAL_CHECKSUM="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"  \
 && if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then >&2 echo 'ERROR: Invalid installer checksum' && rm composer-setup.php && exit 1; fi \
 && php composer-setup.php --quiet --install-dir=/usr/bin --filename=composer \
 && rm composer-setup.php


