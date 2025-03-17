package com.example.springsecuritydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ProtectedController {

    @PreAuthorize("hasRole('ROLE_MOBILE_APP_USER')")
    @GetMapping("/oauth/check")
    public String oauthCheck(Principal principal) {
        String mobileNumber = principal.getName();
        return "oauth check success :"+mobileNumber;
    }
}
