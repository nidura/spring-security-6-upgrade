package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.config.InMemoryTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/token")
public class TokenIntrospectionEndpoint {

    @Autowired
    private InMemoryTokenStore tokenStore;

    /**
     * TODO return real token expiry and scope by retrieving db token
     * @param token
     * @return
     */
    @PostMapping("/introspect")
    public ResponseEntity<Map<String, Object>> introspect(@RequestParam String token) {
        // Look up the token in the token store
        InMemoryTokenStore.TokenDetails tokenDetails = tokenStore.introspect(token);

        if (tokenDetails == null) {
            return new ResponseEntity<>(Map.of("active", false), HttpStatus.OK);
        }

        // Token is valid, return token details
        return new ResponseEntity<>(Map.of(
                "active", true,
                "username", tokenDetails.getUsername(),
                "scope", "read write", // You can customize the scopes for the token here
                "role", tokenDetails.getRoles(),
                "exp", System.currentTimeMillis() / 1000 + 3600 // Expiry (mocked as 1 hour from now)
        ), HttpStatus.OK);
    }
}
