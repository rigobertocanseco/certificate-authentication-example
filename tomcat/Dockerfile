FROM tomcat:9.0

COPY server.xml /usr/local/tomcat/conf/

# add context to /usr/local/tomcat/webapps
COPY certificate-authentication-example-0.0.1-SNAPSHOT.war /usr/local/tomcat/webapps/certificate-authentication-example.war
COPY sample.war /usr/local/tomcat/webapps/sample.war

EXPOSE 8009
