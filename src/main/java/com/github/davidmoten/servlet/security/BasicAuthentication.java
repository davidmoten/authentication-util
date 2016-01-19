package com.github.davidmoten.servlet.security;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.auth.AUTH;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;

public final class BasicAuthentication {
    private final String username;
    private final String password;

    private BasicAuthentication(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public static BasicAuthentication create(String username, String password) {
        return new BasicAuthentication(username, password);
    }

    public static BasicAuthentication from(HttpServletRequest req) {
        String authorization = req.getHeader(AUTH.WWW_AUTH_RESP);
        return from(authorization);
    }

    public static BasicAuthentication from(String authorizationHeader) {
        Preconditions.checkNotNull(authorizationHeader, "authorizationHeader cannot be null");
        Preconditions.checkArgument(authorizationHeader.startsWith(AUTH.WWW_AUTH_RESP + ":"));
        // basic authentication authorization header regex looks like this
        // Authorization:(LWS)*<credentials>
        // where LWS = linear white space (look it up)
        String credentials = authorizationHeader.split(":")[1].trim();
        String[] fields = credentials.split(" ");
        String encodedValue = fields[1];
        String decodedValue = new String(Base64.getDecoder().decode(encodedValue), Charsets.UTF_8);
        String[] items = decodedValue.split(":");
        String username = items[0].trim();
        String password = items[1].trim();
        return create(username, password);
    }

    public String password() {
        return password;
    }

    public String username() {
        return username;
    }
}
