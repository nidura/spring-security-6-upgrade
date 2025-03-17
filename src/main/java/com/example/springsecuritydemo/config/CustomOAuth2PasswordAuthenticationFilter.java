package com.example.springsecuritydemo.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class CustomOAuth2PasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    private CustomTokenService tokenService;

    @Autowired
    private InMemoryTokenStore tokenStore;

    public CustomOAuth2PasswordAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl);  // Filter for "/oauth/token"
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader reader = request.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            stringBuilder.append(line);
        }

        String jsonBody = stringBuilder.toString();
        Map<String, String> requestParams = parseJsonToMap(jsonBody);

        String grantType = requestParams.get("grant_type");
        String authType = requestParams.get("auth_type");
        String clientId = requestParams.get("client_id");
        String pin = requestParams.get("pin");
        String userDeviceId = requestParams.get("device_id");

        //todo implement custom device and pin validations

        if (authType.equals("pin")) {
            User userDetails = new User("755783205", pin, Collections.singletonList(new SimpleGrantedAuthority("ROLE_MOBILE_APP_USER")));
            Authentication authentication = new UsernamePasswordAuthenticationToken("755783205", pin, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return authentication;
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
    }


    //JSON-to-Map parsing (you can use Jackson or Gson for this)
    private Map<String, String> parseJsonToMap(String json) {
        Map<String, String> map = new HashMap<>();
        String[] keyValuePairs = json.replaceAll("[{}\"]", "").split(",");
        for (String pair : keyValuePairs) {
            String[] entry = pair.split(":");
            if (entry.length == 2) {
                map.put(entry[0].trim(), entry[1].trim());
            }
        }
        return map;
    }


    /*
    This method if you need to respond with a token after successful authentication
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Generate access and refresh tokens
        OAuth2AccessToken accessToken = tokenService.generateAccessToken(authResult);
        OAuth2RefreshToken refreshToken = tokenService.generateRefreshToken();

        // Store the token, clientId, and roles in the custom token store
        Set<String> roles = authResult.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toSet());
        //todo temporary token store - use DB to store token
        tokenStore.storeToken(accessToken.getTokenValue(), authResult.getName(), roles);
        // Generate the token response
        String tokenResponse = tokenService.generateTokenResponse(accessToken, refreshToken);

        // Return the token response as JSON
        response.setContentType("application/json");
        response.getWriter().write(tokenResponse);
    }
}
