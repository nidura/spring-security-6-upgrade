package com.example.springsecuritydemo.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomOAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal {

    private final Map<String, Object> attributes;
    private final String token;

    public CustomOAuth2AuthenticatedPrincipal(Map<String, Object> attributes, String token) {
        this.attributes = attributes;
        this.token = token;
    }



    @Override
    public String getName() {
        // Return the "sub" claim which should be the mobile number (or the user identifier)
        Object subClaim = attributes.get("sub");
        if (subClaim != null) {
            return subClaim.toString();
        }
        return null; // If sub is not found, return null
    }

    // Return the attributes
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

	@SuppressWarnings("unchecked")
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		Collection<GrantedAuthority> authority = new ArrayList<>();
		List<String> roles = (List<String>) attributes.get("role");
		if (roles != null) {
			authority.addAll(roles.stream()
                    .map(role -> new SimpleGrantedAuthority(role))
                    .collect(Collectors.toList()));
        };
		return authority;
	}
}
