package com.example.springsecuritydemo.config;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * TODO need to replace this with DB
 */
@Service
public class InMemoryTokenStore {

    private final Map<String, TokenDetails> tokens = new HashMap<>();


    public void storeToken(String accessToken, String username, Set<String> roles) {
        TokenDetails tokenDetails = new TokenDetails(username, roles);
        tokens.put(accessToken, tokenDetails);
    }

    // Validate token by checking if it's in the store
    public TokenDetails introspect(String accessToken) {
        return tokens.get(accessToken); // Return null if token is not found
    }

    public static class TokenDetails {
        private final String username;
        private final  Set<String> roles;

        public TokenDetails(String username,  Set<String> roles) {
            this.username = username;
            this.roles = roles;
        }

        public String getUsername() {
            return username;
        }

        public  Set<String> getRoles() {
            return roles;
        }
    }
}
