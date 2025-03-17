package com.example.springsecuritydemo.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class CustomTokenService {

    // The validity of access and refresh tokens (in seconds)
    private static final long ACCESS_TOKEN_VALIDITY_SECONDS = 3600L; // 1 hour
    private static final long REFRESH_TOKEN_VALIDITY_SECONDS = 3600L; // 1 hour

    // Method to generate access token
    public OAuth2AccessToken generateAccessToken(Authentication authentication) {
        // Generate a unique access token (for demo, using a UUID string as the token)
        String accessTokenValue = UUID.randomUUID().toString();
        Instant now = Instant.now();  // Use Instant for accurate time calculations
        Instant expiration = now.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS);  // Add validity to current time

        Set<String> scopes = new HashSet<>();
        scopes.add("read"); //you can add more scopes if necessary

        // Create and return the OAuth2AccessToken with the generated values
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                TokenType.BEARER,
                accessTokenValue,
                now,
                expiration,
                scopes
        );

        return accessToken;
    }

    // Method to generate refresh token
    public OAuth2RefreshToken generateRefreshToken() {
        String refreshTokenValue = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS);  // Set refresh token expiration

        return new OAuth2RefreshToken(refreshTokenValue, now, expiration);
    }

    // Method to generate the response token structure
    public String generateTokenResponse(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
        // Calculate expires_in as the difference between now and the token's expiration
        long expiresIn = accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();

        String tokenResponse = String.format("{\n" +
                        "    \"access_token\": \"%s\",\n" +
                        "    \"token_type\": \"bearer\",\n" +
                        "    \"refresh_token\": \"%s\",\n" +
                        "    \"expires_in\": %d,\n" +
                        "    \"scope\": \"%s\"\n" +
                        "}",
                accessToken.getTokenValue(),
                refreshToken.getTokenValue(),
                expiresIn,
                String.join(" ", accessToken.getScopes()) // If you have multiple scopes
        );

        return tokenResponse;
    }

}

