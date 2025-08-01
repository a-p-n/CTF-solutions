FROM php:8.2-fpm

RUN apt-get update \
 && apt-get install -y \
      libpq-dev \
      postgresql-client \
      git \
      flex \
      bison \
      unzip \
      nginx \
      bash \
      curl \
      gnupg \
      lsb-release \
      python3 \
 && docker-php-ext-install pdo pdo_pgsql \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
 && apt-get update \
 && apt-get install -y docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

 RUN apt-get update \
     && apt-get install -y \
          git \
          gcc \
          make \
          libseccomp-dev \
          pkg-config \
          protobuf-compiler \
          libprotobuf-dev \
          libnl-3-dev \
          libnl-route-3-dev \
     && git clone https://github.com/google/nsjail /tmp/nsjail \
     && make -C /tmp/nsjail \
     && cp /tmp/nsjail/nsjail /usr/local/bin/ \
     && rm -rf /tmp/nsjail \
     && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /sandbox \
     && chown 1000:1000 /sandbox

WORKDIR /var/www/html

COPY . .

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN composer update --no-dev --optimize-autoloader --no-interaction

RUN mkdir -p var/log var/cache public/submissions \
 && chown -R www-data:www-data var \
 && chmod -R 777 var/log var/cache public/submissions

RUN php bin/console cache:warmup --env=prod \
 && chown -R www-data:www-data var/cache

COPY docker/nginx.conf /etc/nginx/sites-available/default
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/www.conf
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY docker/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

EXPOSE 80

CMD ["/usr/local/bin/start.sh"]
