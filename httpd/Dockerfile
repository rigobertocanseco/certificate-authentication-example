FROM ubuntu:latest

#ENV TZ="Asia/Kolkata"
ENV DEBIAN_FRONTEND="noninteractive"
ENV SITE_NAME rigobertocanseco.dev
ENV URL_SECURE https://${SITE_NAME}:8443/
ENV APACHE_SSL_CERT_CA ca_bundle.crt
ENV APACHE_SSL_CERT certificate.crt
ENV APACHE_SSL_PRIVATE private.key

# Install services, packages and do cleanup
RUN apt-get update && apt-get install -y --no-install-recommends apache2 libapache2-mod-jk

# Copy Apache configuration file
ADD apache2.conf /etc/apache2/apache2.conf
ADD 000-default.conf /etc/apache2/sites-enabled/000-default.conf
ADD worker.properties /etc/libapache2-mod-jk/workers.properties
ADD jk.conf /etc/apache2/mods-available/jk.conf


# Copy Server (pub and key)
# Copy CA Public Key
COPY certs/${APACHE_SSL_CERT_CA} /etc/ssl/certs/${APACHE_SSL_CERT_CA}
COPY certs/${APACHE_SSL_CERT} /etc/ssl/certs/${APACHE_SSL_CERT}
COPY certs/${APACHE_SSL_PRIVATE} /etc/ssl/private/${APACHE_SSL_PRIVATE}

RUN a2enmod proxy \
&& a2enmod ssl \
&& a2enmod proxy_ajp \
&& a2enmod proxy_http \
&& a2enmod proxy_fcgi
#&& a2enmod proxy_balancer

VOLUME ["/var/log/apache2"]

EXPOSE 80 443

CMD ["apachectl", "-k", "start", "-DFOREGROUND"]
