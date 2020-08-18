# Configuración de Apache 2.0 para la autenticación mutua SSL / TLS mediante una autoridad de certificación OpenSSL

### Servidor Apache

#### Configuración de Dockerfile

Para crear una imagen necesitamos construir el [Dockerfile](https://docs.docker.com/engine/reference/builder/), gracias a una serie de directivas nos permite crear una imagen según sea necesario.
Intentamos comprender cuáles son las secciones más importantes del Dockerfile. La primera línea del archivo (como se anticipó anteriormente) hace que el contenedor comience desde la imagen ubuntu: 18.04.  

````shell script
FROM ubuntu:18.04
````
A continuación se muestra la sección sobre variables de entorno que son puramente específicas de Apache HTTP.  
Los valores de estas variables de entorno se pueden cambiar para adaptarse a sus necesidades.

```shell script
# Apache ENVs
ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_SERVER_NAME tls-auth.demo.com
ENV APACHE_SERVER_ADMIN tls-auth@demo.com
ENV APACHE_SSL_CERTS tls-auth.demo.com.cer 
ENV APACHE_SSL_PRIVATE tls-auth.demo.com.key
ENV APACHE_SSL_PORT 10443
ENV APACHE_LOG_LEVEL info
ENV APACHE_SSL_LOG_LEVEL info
ENV APACHE_SSL_VERIFY_CLIENT optional
ENV APACHE_HTTP_PROTOCOLS http/1.1
ENV APPLICATION_URL https://${APACHE_SERVER_NAME}:${APACHE_SSL_PORT}
ENV CLIENT_VERIFY_LANDING_PAGE /error.php
ENV API_BASE_PATH /secure/api
ENV HTTPBIN_BASE_URL http://127.0.0.1:8000${API_BASE_PATH}
```

El primer grupo de cuatro variables es muy claro y no creo que necesiten más explicaciones. Se establecen las siguientes variables y en particular APACHE_SSL_CERTS y APACHE_SSL_PRIVATE:

1. El nombre del archivo que contiene el certificado público del servidor en formato PEM (Privacy-Enhanced Mail);
2. El nombre del archivo que contiene la clave privada (en formato PEM) del certificado público.

El certificado de servidor utilizado en este proyecto fue emitido por una Autoridad de Certificación privada creada ad hoc y obviamente no reconocida.

De forma predeterminada, el puerto HTTPS se establece en 10443 mediante la variable APACHE_SSL_PORT. La variable APPLICATION_URL define la ruta de redireccionamiento si se accede a ella a través de HTTP y no de HTTPS.  

Las variables APACHE_LOG_LEVEL y APACHE_SSL_LOG_LEVEL permiten modificar el nivel de registro general y el específico del módulo SSL. El valor predeterminado se establece en INFO  

Para obtener más información, puede consultar la documentación sobre la directiva LogLevel.   

La variable APACHE_SSL_VERIFY_CLIENT actúa sobre la configuración del proceso de verificación del certificado del lado del cliente.  

Si el valor de la directiva Apache SSLVerifyClient es **opcional** u **opcional_no_ca**, si se produce algún error de validación, se mostrará la página específica definida por la variable CLIENT_VERIFY_LANDING_PAGE.  

La variable APACHE_HTTP_PROTOCOLS especifica la lista de protocolos admitidos para el servidor / host virtual. La lista determina los protocolos permitidos que un cliente puede negociar para este servidor / host.  

La variable APACHE_HTTP_PROTOCOLS especifica la lista de protocolos admitidos para el servidor / host virtual. La lista determina los protocolos permitidos que un cliente puede negociar para este servidor / host.  

Para obtener más información, consulte la documentación del módulo Apache [mod_http2](https://httpd.apache.org/docs/2.4/mod/mod_http2.html).  

La siguiente sección del Dockerfile contiene todas las directivas necesarias para la instalación del software indicado anteriormente.
Dado que la distribución elegida es Ubuntu, el comando apt es responsable de la administración de paquetes y, por lo tanto, de la instalación.

```shell script
# Install services, packages and do cleanup
RUN apt update \
    && apt install -y apache2 \
    && apt install -y php php7.2-fpm \
    && apt install -y curl \
    && apt install -y python3-pip \
    && apt install -y git \
    && rm -rf /var/lib/apt/lists/*
```

La siguiente sección del Dockerfile copia las configuraciones de Apache debidamente modificadas para permitir la autenticación mutua.  
```shell script
# Copy Apache configuration file
COPY configs/httpd/000-default.conf /etc/apache2/sites-available/
COPY configs/httpd/default-ssl.conf /etc/apache2/sites-available/
COPY configs/httpd/ssl-params.conf /etc/apache2/conf-available/
COPY configs/httpd/dir.conf /etc/apache2/mods-enabled/
COPY configs/httpd/ports.conf /etc/apache2/
```

La siguiente sección del Dockerfile copia el par de claves del servidor y el certificado público de la CA.  
```shell script
# Copy Server (pub and key) tls-auth.dontesta.it
# Copy CA (Certification Authority) Public Key
COPY configs/certs/blog.dontesta.it.ca.cer /etc/ssl/certs/
COPY configs/certs/tls-auth.dontesta.it.cer /etc/ssl/certs/
COPY configs/certs/tls-auth.dontesta.it.key /etc/ssl/private/
```

La siguiente sección del Dockerfile copia tres scripts PHP con fines de prueba en la raíz del documento estándar de Apache.  
```shell script
# Copy php samples script and other
COPY configs/www/*.php /var/www/html/
COPY configs/www/assets /var/www/html/assets
COPY configs/www/secure /var/www/html/secure
COPY images/favicon.ico /var/www/html/favicon.ico
```

La siguiente sección del Dockerfile copia el script de punto de entrada que inicia el servidor HTTP Apache.
```shell script
# Copy scripts and entrypoint
COPY scripts/entrypoint /entrypoint
```

La siguiente sección del Dockerfile realiza las siguientes actividades principales:  
1. Habilita el módulo SSL
2. Habilita el módulo de encabezados
3. Habilite el módulo MPM Worker
4. Habilite el módulo HTTP2
5. Habilite los módulos Proxy, HTTP Proxy y FCGI Proxy (Fast CGI)
6. Habilita el sitio SSL predeterminado con la configuración de autenticación mutua
7. Habilite las opciones de configuración para fortalecer la seguridad SSL / TLS
8. Realiza un nuevo hash de los certificados. Esto es necesario para que Apache pueda leer los nuevos certificados.

```shell script
RUN a2enmod ssl \
    && a2enmod headers \
    && a2enmod rewrite \
    && a2dismod mpm_prefork \
    && a2dismod mpm_event \
    && a2enmod mpm_worker \
    && a2enmod proxy_fcgi \
    && a2enmod http2 \
    && a2enmod proxy \
    && a2enmod proxy_http \
    && a2enmod remoteip \
    && a2ensite default-ssl \
    && a2enconf ssl-params \
    && a2enconf php7.2-fpm \
    && c_rehash /etc/ssl/certs/
```
Las dos últimas directivas indicadas en el Dockerfile declaran el puerto HTTPS (APACHE_SSL_PORT) que se debe publicar y el comando a ejecutar para poner en escucha (o listen) el nuevo servicio HTTP de Apache.  

**Directorio**

El proyecto se organiza como se muestra a continuación.

```
├── Dockerfile
├── configs
│    ├── certs
|    |── ...
│    ├── httpd
│    │   ├── 000-default.conf
│    │   ├── default-ssl.conf
│    │   ├── dir.conf
│    │   ├── ports.conf
│    │   └── ssl-params.conf
│    ├── openssl
│    │   └── openssl.cnf
│    └── wwww
└── scripts
    └── entrypoint
```

El directorio configs contiene otras carpetas y archivos, en particular:

1. certs
    * contiene el certificado del servidor (clave pública, clave privada y CSR);
    * contiene el certificado CA (clave pública y clave privada);
    * contiene el certificado de cliente personal para la autenticación del navegador. Están disponibles los siguientes: clave pública, clave privada, CSR, par de claves en formato PKCS # 12;
    * contiene el certificado de cliente que se utilizará para autenticar una aplicación o dispositivo. Están disponibles los siguientes: clave pública, clave privada, CSR, par de claves en formato PKCS # 12; 
2. openssl: contiene el archivo de configuración para la herramienta openssl con la configuración predeterminada;
3. contiene el certificado de cliente personal para la autenticación del navegador. Están disponibles los siguientes: clave pública, clave privada, CSR, par de claves en formato PKCS # 12;
4. www: contiene una interfaz web sencilla;
5. scripts: contiene el script de punto de entrada que inicia el servidor Apache

#### Ejecución del Servidor

La imagen de este proyecto de Docker está disponible en [Dockerhub](https://hub.docker.com/r/amusarra/apache-ssl-tls-mutual-authentication).

A continuación se muestran los comandos para extraer la imagen de Docker alojada en Dockerhub. El primer comando extrae la última versión (etiqueta más reciente), mientras que el segundo comando extrae la versión específica de la imagen que en este caso es la versión 1.0.0.

````shell script
docker pull amusarra/apache-ssl-tls-mutual-authentication
docker pull amusarra/apache-ssl-tls-mutual-authentication:1.0.0
````

Una vez que se ha extraído la imagen de Docker (versión 1.0.0), se puede crear el nuevo contenedor usando el comando a continuación.
Los comandos de compilación y ejecución de Docker deben ejecutarse desde la raíz del directorio del proyecto después de clonar este repositorio.

````shell script
docker build -t apache-ssl-tls-mutual-authentication .
docker run -i -t -d -p 10443:10443 --name=apache-ssl-tls-mutual-authentication apache-ssl-tls-mutual-authentication:lat````
````

Usando el comando docker ps deberíamos poder ver el nuevo contenedor en la lista, como se indica a continuación.
````
CONTAINER ID        IMAGE                                  COMMAND                  CREATED             STATUS              PORTS                      NAMES
bb707fb00e89        amusarra/apache-ssl-tls-mutual-authentication:1.0.0   "/usr/sbin/apache2ct…"   6 seconds ago
````

En este punto de nuestro sistema, deberíamos tener la nueva imagen con el nombre apache-ssl-tls-mutual-authentication y ejecutar el nuevo contenedor llamado apache-ssl-tls-mutual-authentication.

A partir de este momento es posible acceder al servicio de autenticación mutua SSL / TLS mediante el navegador.

Para evitar el error SSL_ERROR_BAD_CERT_DOMAIN desde el navegador accediendo al servicio a través de la URL https://127.0.0.1:10443/, se debe agregar la siguiente línea a su archivo de hosts

````
##
# Servizio di mutua autenticazione via Apache HTTPD
##
127.0.0.1       tls-auth.demo.com
````

En el lado del servidor, todo está listo, pero falta una configuración del lado del cliente; es decir, la instalación del certificado digital personal en su navegador.  

La contraseña de ambos PKCS#12 se establece en: **secreta**. Esta es la contraseña que se utilizará para importar certificados.


Una vez que el certificado de cliente (archivo con extensión .p12) está instalado en su navegador (por ejemplo, Firefox), puede ejecutar la prueba de autenticación mutua con un certificado.


### Certificados

Todos los certificados de muestra disponibles dentro del proyecto se generaron utilizando la herramienta OpenSSL. Todos los siguientes comandos han sido y pueden necesitar ser ejecutados por la raíz del proyecto. Los comandos tienen el objetivo de:

1. Cree su propia Autoridad de Certificación;
2. Cree la clave privada del certificado del servidor y CSR (Solicitud de firma de certificado);
3. Firme el certificado del servidor de la CA (creado anteriormente);
4. Cree claves privadas para certificados de cliente;
5. Cree CSR para certificados de cliente;
6. Firmar certificados de cliente de la CA;
7. Exporte el par de claves en formato PKCS#12.

**Configuración de SSL**

OpenSSL proporciona todas las funciones necesarias para configurar una autoridad de certificación, emitir certificados de servidor web, emitir certificados de cliente y revocar certificados.  OpenSSL proporciona un archivo de configuración que se puede utilizar para conservar los valores predeterminados utilizados dentro del contexto de gestión de una CA

Creamos el archivo configs/openssl/openssl.cnf

````yaml 
[ req ]
default_md = sha512
default_bits = 4096
default_days = 730
distinguished_name = req_distinguished_name

[ ca ]
default_ca = DemoCA # The default ca section

[ req_distinguished_name ]
countryName = Country
countryName_default = IT
countryName_min = 2
countryName_max = 2
localityName = Locality Name (eg, city)
localityName_default = Mx
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = Mexico
organizationName = Organizatio
organizationName_default = Demo Autenticacion Mutua SSL
organizationalUnitName = Organizational Unit Name (eg, section)
commonName = Common Name
commonName_default = Demo Autenticacion Mutua SSL Certification Authority
commonName_max = 64
emailAddress = Email Address
emailAddress_default = info@demo.com
emailAddress_max = 100

[ certauth ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
crlDistributionPoints = @crl

[ server ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
nsCertType = server
crlDistributionPoints = @crl

[ client ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
nsCertType = client
crlDistributionPoints = @crl

[ crl ]
URI=http://ca.demo.com/ca.crl
```` 

**Creación de una autoridad de certificación (Certificate Authority) mediante OpenSSL**

Una autoridad de certificación (CA) crea y administra certificados para servidores web, clientes web, cifrado de correo electrónico, firma de código, etc.
Para nuestros propósitos, querremos configurar una CA para que podamos crear certificados X.509 de servidor web que permitirán el uso de certificados SSL y X.509 de cliente que habilitarán la autenticación de cliente.  

Aunque casi todos los sitios web comerciales utilizan certificados X.509 emitidos por autoridades de certificación públicas reconocidas. También es común que las empresas funcionen como su propia autoridad certificadora para sitios de intranet y extranet. Usaremos OpenSSL en Linux / UNIX para configurar nuestra propia CA y emitir certificados con fines de desarrollo.  

El proceso general para crear un certificado incluye: 
1. Crear una clave privada 
2. Crear una solicitud de certificado 
3. Crear y firmar un certificado a partir de la solicitud de certificado

**Creación de su propia autoridad certificadora**
```shell script
$ openssl req -config ./configs/openssl/openssl.cnf -newkey rsa -nodes \
-keyform PEM -keyout ./configs/certs/blog.demo.com.ca.key \
-x509 -days 3650 -extensions certauth \
-outform PEM -out ./configs/certs/blog.demo.com.ca.cer
```

**Creación de la clave privada del servidor y certificado CSR**
```shell script
$ openssl genrsa -out ./configs/certs/tls-auth.demo.com.key 4096
$ openssl req -config ./configs/openssl/openssl.cnf -new \
-key ./configs/certs/tls-auth.demo.com.key \
-out ./configs/certs/tls-auth.demo.com.req
```

A continuación se muestran los comandos de OpenSSL que se utilizan para crear certificados de cliente.

**Firma del certificado del servidor por parte de la CA**
````shell script
$ openssl x509 -req -in ./configs/certs/tls-auth.demo.com.req -sha512 \
-CA ./configs/certs/blog.demo.com.ca.cer \
-CAkey ./configs/certs/blog.demo.com.ca.key \
-set_serial 100 -extfile ./configs/openssl/openssl.cnf \
-extensions server -days 735 \
-outform PEM -out ./configs/certs/tls-auth.demo.com.cer
````

**Verificación del contenido del certificado de CA**

En este punto tenemos nuestro certificado de CA autofirmado y nuestra clave de CA, que se utilizará para firmar los certificados de servidor web y cliente que creamos. Para verificar el contenido del certificado, use el siguiente comando:  

````shell script
$ openssl x509 -in ./configs/certs/tls-auth.demo.com.cer -text
````

**Creación de claves privadas**

````shell script
$ openssl genrsa -out ./configs/certs/tls-client.demo.com.key 4096
$ openssl genrsa -out ./configs/certs/user.demo.com.key 4096
````

**Creation of CSRs**
````shell script
$ openssl req -config ./configs/openssl/openssl.cnf \
-new -key ./configs/certs/tls-client.demo.com.key \
-out ./configs/certs/tls-client.demo.com.req
$ openssl req -config ./configs/openssl/openssl.cnf \
-new -key ./configs/certs/user.demo.com.key \
-out ./configs/certs/user.demo.com.req
````

**Firma de certificados de cliente por CA**
````shell script
$ openssl x509 -req -in ./configs/certs/tls-client.demo.com.req -sha512 \
-CA ./configs/certs/blog.demo.com.ca.cer \
-CAkey ./configs/certs/blog.demo.com.ca.key \
-set_serial 200 -extfile ./configs/openssl/openssl.cnf \
-extensions client -days 365 \
-outform PEM -out ./configs/certs/tls-client.demo.com.cer
$ openssl x509 -req -in ./configs/certs/user.demo.com.req -sha512 \
-CA ./configs/certs/blog.demo.com.ca.cer \
-CAkey ./configs/certs/blog.demo.com.ca.key \
-set_serial 400 -extfile ./configs/openssl/openssl.cnf \
-extensions client -days 365 -outform PEM \
-out ./configs/certs/user.demo.com.cer
````

**Exportación del par de claves en formato PKCS # 12**
````shell script
$ openssl pkcs12 -export -inkey ./configs/certs/tls-client.dontesta.it.key \
-in ./configs/certs/tls-client.demo.com.cer \
-out ./configs/certs/tls-client.demo.com.p12
$ openssl pkcs12 -export -inkey ./configs/certs/user.demo.com.key \
-in ./configs/certs/user.demo.com.cer \
-out ./configs/certs/user.demo.com.p12
````

### Aplicación web

### Links 
[http://www.cafesoft.com/products/cams/ps/docs32/admin/ConfiguringApache2ForSSLTLSMutualAuthentication.html#Creating_a_Certificate_Authority_using_OpenSSL](http://www.cafesoft.com/products/cams/ps/docs32/admin/ConfiguringApache2ForSSLTLSMutualAuthentication.html#Creating_a_Certificate_Authority_using_OpenSSL)
[https://dzone.com/articles/apache-http-24-how-to-build-a-docker-image-for-ssl](https://dzone.com/articles/apache-http-24-how-to-build-a-docker-image-for-ssl)