FROM python:3.11-slim
LABEL maintainer="github/alfonsrv <alfonsrv@protonmail.com>"

ENV APACHE_CONFDIR=/etc/apache2

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    apache2 libapache2-mod-wsgi-py3 \
    krb5-k5tls \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN a2enmod wsgi \
    && a2enmod ssl \
    && a2enmod headers \
    && a2enmod setenvif

RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log && \
    ln -sf /proc/self/fd/1 /var/log/apache2/error.log

COPY config/kdc-wsgi.conf ${APACHE_CONFDIR}/sites-available/

# Download + install kdcproxy and get install path to replace in apache config
RUN git clone https://github.com/latchset/kdcproxy.git /tmp/kdcproxy \
    && pip install /tmp/kdcproxy \
    && KDC_PROXY_PATH=$(python -c "import site; print(site.getsitepackages()[0])")/kdcproxy \
    && sed -ri -e "s!KDC_PROXY_PATH!${KDC_PROXY_PATH}!g" /etc/apache2/sites-available/*.conf \
    && sed -ri -e "s!SERVER_NAME!${SERVER_NAME}!g" /etc/apache2/sites-available/*.conf

RUN a2dissite 000-default.conf \
    && a2ensite kdc-wsgi.conf

CMD ["apachectl", "-D",  "FOREGROUND"]