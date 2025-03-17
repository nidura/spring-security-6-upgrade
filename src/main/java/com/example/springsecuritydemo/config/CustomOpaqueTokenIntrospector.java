package com.example.springsecuritydemo.config;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final RestTemplate restTemplate;
    private final Map<String, String> clientCredentials; // Map to store multiple clients
    private final String introspectionUri;

    public CustomOpaqueTokenIntrospector(String introspectionUri, Map<String, String> clientCredentials) {
        this.restTemplate = new RestTemplate();
        this.introspectionUri = introspectionUri;
        this.clientCredentials = clientCredentials;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        try {
            for (Map.Entry<String, String> entry : clientCredentials.entrySet()) {
                String clientId = entry.getKey();
                String clientSecret = entry.getValue();
                
                MultiValueMap<String, String> rbody = new LinkedMultiValueMap<>();
                rbody.add("token", token);

                // Set headers
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
                headers.setBasicAuth(clientId, clientSecret);

                // Create HttpEntity with headers and body
                HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(rbody, headers);
                
                ResponseEntity<Map> response = restTemplate.exchange(
                    introspectionUri,
                    HttpMethod.POST,
                    request,
                    Map.class
                );

                if (response.getStatusCode() == HttpStatus.OK) {
                    Map<String, Object> body = response.getBody();
                    if (body != null && Boolean.TRUE.equals(body.get("active"))) {
                        if (body.get("exp") instanceof Integer) {
                            Integer exp = (Integer) body.get("exp");
                            body.put("exp", Instant.ofEpochSecond(exp.longValue())); // Convert to Instant
                        }
                        // Ensure that the "sub" claim (mobile number) is present in the attributes
                        body.put("sub", body.get("sub"));

                        // Create a custom principal
                        return new CustomOAuth2AuthenticatedPrincipal(body, token);
                    }
                }
            }

            throw new OAuth2IntrospectionException("Provided token isn't active or introspection failed");

        } catch (HttpClientErrorException e) {
            throw new OAuth2IntrospectionException("Introspection endpoint responded with " + e.getStatusCode(), e);
        }
    }
}
