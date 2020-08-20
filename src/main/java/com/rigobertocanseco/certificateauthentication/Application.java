package com.rigobertocanseco.certificateauthentication;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.ajp.AbstractAjpProtocol;
import org.apache.coyote.ajp.AjpNioProtocol;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

import java.security.Principal;

@SpringBootApplication
@RestController
public class Application extends SpringBootServletInitializer {


    @RequestMapping("/")
    public String home() {
        return "Hello Docker World 222";
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /*
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addAdditionalTomcatConnectors(redirectConnector());
        return tomcat;
    }

    private Connector redirectConnector2() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        Connector ajpConnector = new Connector("org.apache.coyote.ajp.AjpNioProtocol");
        AjpNioProtocol protocol= (AjpNioProtocol)ajpConnector.getProtocolHandler();
        protocol.setSecret("myapjsecret");
        ajpConnector.setPort(9090);
        ajpConnector.setSecure(true);
        return ajpConnector;
    }

    private Connector redirectConnector() {
        Connector ajpConnector = new Connector("AJP/1.3");
        ajpConnector.setPort(9090);
        ajpConnector.setSecure(false);
        ajpConnector.setAllowTrace(false);
        ajpConnector.setScheme("http");
        ((AbstractAjpProtocol) ajpConnector.getProtocolHandler()).setSecretRequired(false);
        /*
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        if (tomcatAjpEnabled) {
            Connector ajpConnector = new Connector("AJP/1.3");
            ajpConnector.setPort(ajpPort);
            ajpConnector.setSecure(false);
            ajpConnector.setAllowTrace(false);
            ajpConnector.setScheme("https");
            tomcat.addAdditionalTomcatConnectors(ajpConnector);
            }

        return ajpConnector;
    }
     */
}