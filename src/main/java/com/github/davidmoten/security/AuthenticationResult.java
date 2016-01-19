package com.github.davidmoten.security;

import java.util.Map;

public final class AuthenticationResult {

    private final boolean authorized;
    private final Map<String, String[]> parameters;

    public AuthenticationResult(boolean authorized, Map<String, String[]> parameters) {
        this.authorized = authorized;
        this.parameters = parameters;
    }

    public boolean isAuthorized() {
        return authorized;
    }

    public Map<String, String[]> parameters() {
        return parameters;
    }

}
