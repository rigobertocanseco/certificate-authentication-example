# Configuración de Apache 2.0 para la autenticación mutua SSL / TLS

## Introduccón

La [autenticación mutua](https://en.wikipedia.org/wiki/Mutual_authentication) o autenticación bidireccional se refiere a dos partes que se autentican entre sí al mismo tiempo, siendo un modo de autenticación predeterminado en algunos protocolos (IKE, SSH) y opcional en otros ([TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)).  

Por defecto, el protocolo TLS solo prueba la identidad del servidor al cliente mediante el certificado [X.509](https://en.wikipedia.org/wiki/X.509#Certificates) y la autenticación del cliente en el servidor se deja a la capa de aplicación.

TLS también ofrece autenticación de cliente a servidor mediante la autenticación X.509 del lado del cliente. Como requiere el aprovisionamiento de certificados a los clientes e implica una experiencia menos fácil de usar, rara vez se usa en aplicaciones de usuario final.

La autenticación Mutua (TLS) es mucho más utilizada en aplicaciones B2B, donde un número limitado de clientes programáticos y homogéneos se conectan a servicios web específicos, la carga operativa es limitada y los requisitos de seguridad suelen ser mucho más altos en comparación con los entornos de consumo.

Desde un punto de vista de alto nivel, el proceso de autenticación y creación de un canal cifrado mediante la autenticación mutua basada en certificados (o autenticación mutua) implica los siguientes pasos:

1. Un cliente solicita acceso a un recurso protegido;
2. El servidor presenta su certificado al cliente;
3. El cliente verifica el certificado del servidor;
4. Si tiene éxito, el cliente envía su certificado al servidor;
5. El servidor verifica las credenciales del cliente;
6. Si tiene éxito, el servidor otorga acceso al recurso protegido solicitado por el cliente.

![**Figura 1: Qué sucede durante el proceso de autenticación mutua**](https://raw.githubusercontent.com/amusarra/docker-apache-ssl-tls-mutual-authentication/master/images/security-sslBMAWithCertificates.gif)

### Servidor Apache

#### Equipo 
**Hardware:**  

- Sistema Operativo: Debian 10, x86-64 
- Núcleo de Linux: 4.19.0-10-amd64
- Memoria RAM: 6GB
- IntellijIdea
- JVM 

**Software**  

- Apache HTTP 2.4 (2.4.41-1ubuntu1)
- PHP 7.3 (7.3.11-0ubuntu0.19.10.2)
- PHP 7.3 FPM (FastCGI Process Manager)
- Docker 
	- Client: Docker Engine - Community  
 Version:           19.03.12
	- Server: Docker Engine - Community  
 Engine:
  Version:          19.03.12
	- Container: [https://hub.docker.com/r/amusarra/apache-ssl-tls-mutual-authentication](https://hub.docker.com/r/amusarra/apache-ssl-tls-mutual-authentication)  


#### Configuración de Dockerfile

Una vez que tengamos los cubiertos los requisitos mínimos para desarrollar la aplicación vamos a tener que instalar [Docker](https://docs.docker.com/), que nos va a servir como un contenedor para nuestra aplicación donde vamos a tener instalado nuestro servidor con todo lo necesario como es: sistema operativo, apache.

Descargamos el siguiente [contenedor](https://hub.docker.com/r/amusarra/apache-ssl-tls-mutual-authentication)

Para crear una imagen necesitamos construir el [Dockerfile](https://docs.docker.com/engine/reference/builder/), gracias a una serie de directivas nos permite crear una imagen según sea necesario.
Intentamos comprender cuáles son las secciones más importantes del Dockerfile. La primera línea del archivo (como se anticipó anteriormente) hace que el contenedor comience desde la imagen ubuntu: 18.04.  

````shell script
FROM ubuntu:19.10
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
ENV APACHE_SSL_PORT 443
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

De forma predeterminada, el puerto HTTPS se establece en 443 mediante la variable APACHE_SSL_PORT. La variable APPLICATION_URL define la ruta de redireccionamiento si se accede a ella a través de HTTP y no de HTTPS.  

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
docker run -i -t -d -p 443:443 --name=apache-ssl-tls-mutual-authentication apache-ssl-tls-mutual-authentication
````

Usando el comando docker ps deberíamos poder ver el nuevo contenedor en la lista, como se indica a continuación.
````
CONTAINER ID        IMAGE                                  COMMAND                  CREATED             STATUS              PORTS                      NAMES
bb707fb00e89        amusarra/apache-ssl-tls-mutual-authentication:1.0.0   "/usr/sbin/apache2ct…"   6 seconds ago
````

En este punto de nuestro sistema, deberíamos tener la nueva imagen con el nombre apache-ssl-tls-mutual-authentication y ejecutar el nuevo contenedor llamado apache-ssl-tls-mutual-authentication.

A partir de este momento es posible acceder al servicio de autenticación mutua SSL / TLS mediante el navegador.

Para evitar el error SSL_ERROR_BAD_CERT_DOMAIN desde el navegador accediendo al servicio a través de la URL https://127.0.0.1:443/, se debe agregar la siguiente línea a su archivo de hosts

````
127.0.0.1       demo.com
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
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 100 (0x64)
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C = MX, L = Mx, ST = Mexico, O = Demo Autenticacion Mutua SSL, CN = Demo Autenticacion Mutua SSL Certification Authority, emailAddress = info@demo.com
        Validity
            Not Before: Aug 19 16:33:55 2020 GMT
            Not After : Aug 24 16:33:55 2022 GMT
        Subject: C = MX, L = Mx, ST = Mexico, O = Demo Autenticacion Mutua SSL, CN = Demo Autenticacion Mutua SSL Certification Authority, emailAddress = info@demo.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:c1:37:19:20:c9:8f:87:16:f2:6e:40:8d:5b:0c:
                    73:2a:d9:24:a2:aa:b4:7d:0f:00:c0:57:f6:f6:7e:
                    f2:9c:43:77:4d:51:68:42:75:00:b9:64:17:0a:65:
                    4e:a8:f7:88:51:93:71:16:53:16:c0:50:d4:22:62:
                    b4:7f:59:76:e0:ee:ae:8d:56:e2:71:0c:20:c6:94:
                    4b:9a:06:4c:98:40:e4:7d:f0:55:bf:3d:f9:c7:a7:
                    f6:78:c6:43:14:e4:da:34:01:f8:86:34:1b:30:39:
                    32:5d:fa:23:cb:2a:12:18:58:21:dd:ad:eb:62:fe:
                    08:5a:47:c6:a2:a9:e1:2b:5a:9a:5d:db:c2:83:c1:
                    05:1a:bf:c6:7c:fe:e4:72:71:dd:85:33:6a:f4:27:
                    9f:82:63:5b:f9:ef:0d:11:57:4f:d9:5d:34:fa:59:
                    03:cb:77:95:9d:65:ba:64:6f:4f:4e:55:88:e2:5f:
                    44:e6:c9:32:4a:ec:b2:e1:60:1b:36:83:3d:0d:4d:
                    55:70:a4:87:52:a4:85:51:48:c9:d4:b4:c4:b1:36:
                    64:d1:4d:c0:2f:c0:07:f0:f6:ef:ef:a7:3a:f5:68:
                    f3:76:a6:aa:02:27:2f:8e:cd:2a:40:cb:9b:01:da:
                    7b:30:3e:71:df:dd:91:0a:2f:ed:4e:3d:50:ec:fc:
                    72:4a:c7:71:f7:c6:eb:77:e0:30:42:05:97:71:6f:
                    33:bd:00:8a:fc:dd:99:cd:ce:d0:38:93:21:ce:ce:
                    69:14:91:39:62:4f:69:42:eb:70:d1:1c:55:34:88:
                    ba:6b:4c:78:6c:07:01:5c:f4:06:2e:d9:da:88:b9:
                    66:5e:eb:d3:3a:24:d5:1a:ee:08:39:6d:f0:5f:42:
                    b9:a3:7b:0b:5f:25:2b:e5:e1:87:93:fb:a4:b9:45:
                    b7:ee:4f:bd:1a:a5:d9:89:7d:6a:6b:88:5a:e1:2d:
                    6d:9d:62:90:34:c2:8c:e6:60:a7:32:12:4a:e8:f9:
                    36:00:e7:80:6c:e1:eb:18:f7:d1:8b:8b:57:8d:25:
                    39:9a:ab:ef:e0:01:f6:0b:79:66:2e:8d:1a:46:6e:
                    f7:f9:e5:98:9d:c5:55:c7:49:3c:f5:80:bd:89:b5:
                    e4:fb:5d:fc:9d:a5:91:09:a4:f9:e0:2e:f7:7e:67:
                    d6:d7:ce:fa:b6:23:a4:e5:b2:6e:ff:a7:3c:df:af:
                    e1:85:1e:f6:b6:e1:5a:74:3a:e6:63:e2:0c:7b:4d:
                    7b:0e:e2:b4:80:fb:f4:ba:7d:74:73:c4:fb:99:d9:
                    99:fa:e8:98:66:1b:a3:f4:77:32:f7:90:34:71:cf:
                    e7:b4:97:74:d3:16:71:5d:79:f8:f8:64:85:4e:42:
                    2b:b2:a1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature, Key Encipherment, Data Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            Netscape Cert Type:
                SSL Server
            X509v3 CRL Distribution Points:

                Full Name:
                  URI:http://ca.demo.com/ca.crl

    Signature Algorithm: sha512WithRSAEncryption
         0c:50:4a:3c:8b:30:6a:82:e0:7c:a2:ca:02:d5:00:c8:54:17:
         1e:d7:1d:98:d3:7d:9f:fb:d9:bf:bc:c9:d4:a9:16:ba:7b:fb:
         14:6a:13:65:b3:68:05:ea:02:43:62:2a:9d:61:99:52:27:8b:
         95:fb:93:d3:f5:fe:28:53:53:a8:cb:23:f2:4d:d3:43:42:9f:
         53:4c:11:28:c1:cb:13:84:13:34:67:dc:ca:c8:e9:78:50:7a:
         cb:f1:45:e5:00:50:f5:ec:eb:b8:cc:6e:36:88:27:8c:24:93:
         dc:b0:15:d7:f4:ca:b0:20:ed:32:0b:48:c6:47:ee:fe:fd:19:
         9f:b4:a7:1d:3c:74:f9:8a:a8:5e:bb:77:a2:3e:62:78:fd:5d:
         95:1a:69:7d:a8:47:68:4e:b4:6d:f4:2b:4b:cd:00:73:24:1e:
         0b:27:9d:52:25:4d:0d:6e:27:ef:65:db:b0:08:9c:8f:d7:a4:
         d6:4d:49:af:33:c1:73:8a:e0:78:53:13:69:16:d9:60:53:98:
         f1:07:00:11:6e:3a:75:e5:95:bc:0d:d1:35:e7:6a:a0:af:c3:
         c5:c5:9d:db:9f:bc:25:a7:84:74:c5:60:75:52:6e:70:66:17:
         e6:a2:05:3e:b7:79:ba:d1:04:37:7b:62:fe:3d:3d:51:63:f1:
         9b:11:36:8a:d1:1f:5e:ca:2d:f8:83:fb:c8:30:55:33:94:63:
         db:2c:03:d5:6e:f2:7c:ec:0b:f3:79:63:c3:98:ea:e1:e8:7c:
         6c:46:6a:af:c4:5d:1c:f8:96:50:af:b7:62:c4:c3:d2:df:ef:
         64:62:71:20:6f:f8:f6:7e:53:fc:d6:33:8b:a5:ca:63:02:8b:
         43:32:91:12:52:02:da:0c:f5:65:23:24:34:15:5d:a4:7d:fd:
         fb:20:33:ac:36:61:b3:6b:90:fe:52:8d:94:4f:6e:6e:de:be:
         c1:7b:32:55:83:ef:06:5d:cd:55:13:b9:84:33:d9:6f:62:22:
         8c:66:85:75:b0:24:17:5b:f3:e6:32:cd:55:85:9d:2e:c4:48:
         b6:27:d9:96:23:f9:90:e5:eb:5c:17:dd:83:fe:4e:8b:dd:e4:
         f4:71:51:de:67:ba:3a:66:22:ae:81:81:f5:74:28:86:34:45:
         61:8c:d5:e4:38:5d:44:80:d6:af:7d:80:79:98:87:27:e4:04:
         fb:08:f4:80:09:61:80:12:32:4d:71:e8:37:8b:43:79:0a:e5:
         bc:12:a7:ab:50:ae:f2:55:a0:c0:01:70:57:38:42:3d:c5:72:
         f2:c2:37:07:df:76:fa:c2:62:9b:7c:75:46:11:18:db:c7:c8:
         e3:44:3d:1f:09:76:3c:55
-----BEGIN CERTIFICATE-----
MIIGSTCCBDGgAwIBAgIBZDANBgkqhkiG9w0BAQ0FADCBrzELMAkGA1UEBhMCTVgx
CzAJBgNVBAcMAk14MQ8wDQYDVQQIDAZNZXhpY28xJTAjBgNVBAoMHERlbW8gQXV0
ZW50aWNhY2lvbiBNdXR1YSBTU0wxPTA7BgNVBAMMNERlbW8gQXV0ZW50aWNhY2lv
biBNdXR1YSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxHDAaBgkqhkiG9w0B
CQEWDWluZm9AZGVtby5jb20wHhcNMjAwODE5MTYzMzU1WhcNMjIwODI0MTYzMzU1
WjCBrzELMAkGA1UEBhMCTVgxCzAJBgNVBAcMAk14MQ8wDQYDVQQIDAZNZXhpY28x
JTAjBgNVBAoMHERlbW8gQXV0ZW50aWNhY2lvbiBNdXR1YSBTU0wxPTA7BgNVBAMM
NERlbW8gQXV0ZW50aWNhY2lvbiBNdXR1YSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRo
b3JpdHkxHDAaBgkqhkiG9w0BCQEWDWluZm9AZGVtby5jb20wggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDBNxkgyY+HFvJuQI1bDHMq2SSiqrR9DwDAV/b2
fvKcQ3dNUWhCdQC5ZBcKZU6o94hRk3EWUxbAUNQiYrR/WXbg7q6NVuJxDCDGlEua
BkyYQOR98FW/PfnHp/Z4xkMU5No0AfiGNBswOTJd+iPLKhIYWCHdreti/ghaR8ai
qeErWppd28KDwQUav8Z8/uRycd2FM2r0J5+CY1v57w0RV0/ZXTT6WQPLd5WdZbpk
b09OVYjiX0TmyTJK7LLhYBs2gz0NTVVwpIdSpIVRSMnUtMSxNmTRTcAvwAfw9u/v
pzr1aPN2pqoCJy+OzSpAy5sB2nswPnHf3ZEKL+1OPVDs/HJKx3H3xut34DBCBZdx
bzO9AIr83ZnNztA4kyHOzmkUkTliT2lC63DRHFU0iLprTHhsBwFc9AYu2dqIuWZe
69M6JNUa7gg5bfBfQrmjewtfJSvl4YeT+6S5RbfuT70apdmJfWpriFrhLW2dYpA0
wozmYKcyEkro+TYA54Bs4esY99GLi1eNJTmaq+/gAfYLeWYujRpGbvf55ZidxVXH
STz1gL2JteT7XfydpZEJpPngLvd+Z9bXzvq2I6Tlsm7/pzzfr+GFHva24Vp0OuZj
4gx7TXsO4rSA+/S6fXRzxPuZ2Zn66JhmG6P0dzL3kDRxz+e0l3TTFnFdefj4ZIVO
QiuyoQIDAQABo24wbDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIEsDATBgNVHSUEDDAK
BggrBgEFBQcDATARBglghkgBhvhCAQEEBAMCBkAwKgYDVR0fBCMwITAfoB2gG4YZ
aHR0cDovL2NhLmRlbW8uY29tL2NhLmNybDANBgkqhkiG9w0BAQ0FAAOCAgEADFBK
PIswaoLgfKLKAtUAyFQXHtcdmNN9n/vZv7zJ1KkWunv7FGoTZbNoBeoCQ2IqnWGZ
UieLlfuT0/X+KFNTqMsj8k3TQ0KfU0wRKMHLE4QTNGfcysjpeFB6y/FF5QBQ9ezr
uMxuNognjCST3LAV1/TKsCDtMgtIxkfu/v0Zn7SnHTx0+YqoXrt3oj5ieP1dlRpp
fahHaE60bfQrS80AcyQeCyedUiVNDW4n72XbsAicj9ek1k1JrzPBc4rgeFMTaRbZ
YFOY8QcAEW46deWVvA3RNedqoK/DxcWd25+8JaeEdMVgdVJucGYX5qIFPrd5utEE
N3ti/j09UWPxmxE2itEfXsot+IP7yDBVM5Rj2ywD1W7yfOwL83ljw5jq4eh8bEZq
r8RdHPiWUK+3YsTD0t/vZGJxIG/49n5T/NYzi6XKYwKLQzKRElIC2gz1ZSMkNBVd
pH39+yAzrDZhs2uQ/lKNlE9ubt6+wXsyVYPvBl3NVRO5hDPZb2IijGaFdbAkF1vz
5jLNVYWdLsRItifZliP5kOXrXBfdg/5Oi93k9HFR3me6OmYiroGB9XQohjRFYYzV
5DhdRIDWr32AeZiHJ+QE+wj0gAlhgBIyTXHoN4tDeQrlvBKnq1Cu8lWgwAFwVzhC
PcVy8sI3B992+sJim3x1RhEY28fI40Q9Hwl2PFU=
-----END CERTIFICATE-----
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
$ openssl pkcs12 -export -inkey ./configs/certs/tls-auth.demo.com.key \
-in ./configs/certs/tls-auth.demo.com.cer \
-out ./configs/certs/tls-auth.demo.com.p12

$ openssl pkcs12 -export -inkey ./configs/certs/tls-client.demo.com.key \
-in ./configs/certs/tls-client.demo.com.cer \
-out ./configs/certs/tls-client.demo.com.p12

$ openssl pkcs12 -export -inkey ./configs/certs/user.demo.com.key \
-in ./configs/certs/user.demo.com.cer \
-out ./configs/certs/user.demo.com.p12
````

**Descripción de los comandos utilizados**

openssl: Comando para ejecutar OpenSSL
* req: Solicitud de certificado(CSR) y generación de certificado
    * -config ./configs/openssl/openssl.cnf :Archivo de configuración para OpenSSL
    * -newkey rsa: Opción para crear un nuevo CSR y una nueva llave privada, rsa genera una llave RSA
    * -nodes: Una clave privada creada no se cifrará.
    * -keyform PEM: Formato de la llave
    * -keyout ./configs/certs/blog.demo.com.ca.key: Donde se almacenará la llave
    * -x509: Se utiliza para generar un certificado autofirmado.
    * -days 3650: Numero de dias de duración del certificado
    * -extensions certauth: La sección desde la que agregar extensiones de certificado.
    * -outform PEM: Formato de la llave
    * -out ./configs/certs/blog.demo.com.ca.cer: Salida del certificado

* genrsa: Generación de clave privada RSA 
    * -out: ./configs/certs/tls-auth.demo.com.key: Salida de la llave
    * 4096: Significa generar una clave RSA nbits de tamaño.

* x509: X.509 Certificate Data Management
    * -req: Con esta opción, se espera una solicitud de certificado(CSR)
    * -in ./configs/certs/tls-auth.demo.com.req: Certificado CSR
    * -sha512: Muestra el certificado en SHA512
    * -CA ./configs/certs/blog.demo.com.ca.cer: Especifica el certificado de CA que se utilizará para firmar.
    * -CAkey ./configs/certs/blog.demo.com.ca.key: Establece la clave privada de CA con la que firmar un certificado.
    * -set_serial 100: Especifica el número de serie que se utilizará. 
    * -extfile ./configs/openssl/openssl.cnf: Archivo de configuración
    * -extensions server: La sección desde la que agregar extensiones de certificado.
    * -days 735: Numero de dias de duración del certificado 
    * -outform PEM. Formato ddel certificado
    * -out ./configs/certs/tls-auth.demo.com.cer: Salida del certificado
* pkcs12: Utilidad de OpenSSL PKCS12 
    * -export: La opción especifica que se creará un archivo PKCS#12. 
    * -inkey ./configs/certs/user.demo.com.key: Archivo para leer la llave privada
    * -in ./configs/certs/user.demo.com.cer: Archivo para leer el certificado
    * -out ./configs/certs/user.demo.com.p12: Donde se almacenara el PKCS#12

**Generar almacén de confianza del Auth a partir del certificado del Auth**
````shell script
$ keytool -import -trustcacerts -alias root -file ./configs/certs/tls-auth.demo.com.cer -keystore ./configs/certs/tls-auth.demo.com.jks
.com.jks
Enter keystore password:
Re-enter new password:
Owner: EMAILADDRESS=auth@demo.com, CN=Demo Uthentication Mutua SSL Auth, O=Demo Autenticacion Mutua SSL, ST=Mexico, L=Mx, C=MX
Issuer: EMAILADDRESS=info@demo.com, CN=Demo Autenticacion Mutua SSL Certification Authority, O=Demo Autenticacion Mutua SSL, ST=Mexico, L=Mx, C=MX
Serial number: 64
Valid from: Wed Aug 19 12:12:48 CDT 2020 until: Wed Aug 24 12:12:48 CDT 2022
Certificate fingerprints:
         SHA1: DB:D8:C7:F5:99:B9:51:3E:01:64:CC:44:4D:4F:BA:A3:DF:9C:28:01
         SHA256: CA:D6:B6:DB:23:7B:3C:41:CF:E6:B2:0E:A6:88:81:BA:74:CB:A3:4B:A1:0F:C1:21:FD:A9:04:F4:2B:AD:CD:A1
Signature algorithm name: SHA512withRSA
Subject Public Key Algorithm: 4096-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.19 Criticality=false
BasicConstraints:[
  CA:false
  PathLen: undefined
]

#2: ObjectId: 2.5.29.31 Criticality=false
CRLDistributionPoints [
  [DistributionPoint:
     [URIName: http://ca.demo.com/ca.crl]
]]

#3: ObjectId: 2.5.29.37 Criticality=false
ExtendedKeyUsages [
  serverAuth
]

#4: ObjectId: 2.5.29.15 Criticality=false
KeyUsage [
  DigitalSignature
  Key_Encipherment
  Data_Encipherment
]

#5: ObjectId: 2.16.840.1.113730.1.1 Criticality=false
NetscapeCertType [
   SSL server
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
````

### Aplicación web

### Pruebas

Una vez que esté corriendo el servidor ingresamos a https://demo.com:8443/ en el navegador




### Links 
[https://en.wikipedia.org/wiki/Mutual_authentication](https://en.wikipedia.org/wiki/Mutual_authentication)  
[https://httpd.apache.org/docs/2.4/](https://httpd.apache.org/docs/2.4/)  
[https://docs.oracle.com/cd/E19798-01/821-1841/gijrp/index.html](https://docs.oracle.com/cd/E19798-01/821-1841/gijrp/index.html])
[https://spring.io/guides/gs/spring-boot-docker/](https://spring.io/guides/gs/spring-boot-docker/)
[https://stormpath.com/blog/secure-spring-boot-webapp-apache-letsencrypt-ssl](https://stormpath.com/blog/secure-spring-boot-webapp-apache-letsencrypt-ssl)
[https://github.com/amusarra/docker-apache-ssl-tls-mutual-authentication](https://github.com/amusarra/docker-apache-ssl-tls-mutual-authentication)  
[https://github.com/codependent/spring-boot-ssl-mutual-authentication](https://github.com/codependent/spring-boot-ssl-mutual-authentication)
[http://www.cafesoft.com/products/cams/ps/docs32/admin/ConfiguringApache2ForSSLTLSMutualAuthentication.html#Creating_a_Certificate_Authority_using_OpenSSL](http://www.cafesoft.com/products/cams/ps/docs32/admin/ConfiguringApache2ForSSLTLSMutualAuthentication.html#Creating_a_Certificate_Authority_using_OpenSSL)
[https://dzone.com/articles/apache-http-24-how-to-build-a-docker-image-for-ssl](https://dzone.com/articles/apache-http-24-how-to-build-a-docker-image-for-ssl)  
[https://medium.com/@niral22/2-way-ssl-with-spring-boot-microservices-2c97c974e83](https://medium.com/@niral22/2-way-ssl-with-spring-boot-microservices-2c97c974e83)  
[https://stackoverflow.com/questions/52346639/spring-boot-and-apache2-on-the-same-server-and-port](https://stackoverflow.com/questions/52346639/spring-boot-and-apache2-on-the-same-server-and-port)
[https://www.baeldung.com/x-509-authentication-in-spring-security](https://www.baeldung.com/x-509-authentication-in-spring-security)
https://github.com/Paritosh-Anand/Docker-Httpd-Tomcat
https://docs.jelastic.com/tomcat-behind-apache/
https://medium.com/@iamvickyav/deploying-spring-boot-war-in-tomcat-based-docker-2b689b206496
https://careydevelopment.us/2017/06/19/run-spring-boot-apache-web-server-front-end/
https://www.howtobuildsoftware.com/index.php/how-do/bD28/java-tomcat-ssl-mutual-authentication-mutual-authentication-with-tomcat-7
https://www.naschenweng.info/2018/02/01/java-mutual-ssl-authentication-2-way-ssl-authentication/
