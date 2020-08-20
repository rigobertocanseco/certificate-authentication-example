package com.rigobertocanseco.certificateauthentication;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @RequestMapping(value = "/user")
    public String user(Model model, Principal principal) {
        UserDetails currentUser = (UserDetails) ((Authentication) principal).getPrincipal();
        System.out.println("UserDetails:" + currentUser);
        System.out.println("Principal:" + principal);
        System.out.println("Username:" + currentUser.getUsername());
        model.addAttribute("username", currentUser.getUsername());
        return "<!DOCTYPE html>\n" +
                "<html xmlns:th=\"http://www.thymeleaf.org\">\n" +
                "<head>\n" +
                "    <title>X.509 Authentication Demo</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<h2>Hello "+ currentUser.getUsername() + "!</h2>\n" +
                "</body>\n" +
                "</html>";
    }
}