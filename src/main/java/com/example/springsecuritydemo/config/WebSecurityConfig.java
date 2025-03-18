package com.example.springsecuritydemo.config;

import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    //todo config in property
    private final String introspectionUri = "http://localhost:8080/oauth/introspect"; // Your introspection endpoint


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        Map<String, String> clientCredentials = new HashMap<>();
        //todo config in property. use specific client for introspect - like introspect_api_client
        clientCredentials.put("mobile_api_client", "6f6b8a16-e356-4850-bdde-423d36321940");

        http
                .csrf(csrf -> csrf.disable()) // Disable CSRF
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth/token", "/login","/token/introspect","/health/check").permitAll() // Allow public access to auth endpoints
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer
                                .opaqueToken(opaqueTokenConfigurer ->
                                        opaqueTokenConfigurer
                                                .introspector(new CustomOpaqueTokenIntrospector(
                                                        introspectionUri,
                                                        clientCredentials
                                                ))
                                )
                );

        // Add the custom OAuth2PasswordAuthenticationFilter before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(customOAuth2PasswordAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class
        );
        return http.build();
    }

    @Bean
    public CustomOAuth2PasswordAuthenticationFilter customOAuth2PasswordAuthenticationFilter(HttpSecurity http) throws Exception {
        return new CustomOAuth2PasswordAuthenticationFilter("/oauth/token", authenticationManager(http));
    }

}
