package com.github.davidmoten.security;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import com.google.common.base.Preconditions;

public final class AuthenticatorHmac {

    private AuthenticatorHmac() {
        // prevent instantiation
    }

    public static AuthenticationResult authenticate(HttpServletRequest req, KeyProvider keyProvider,
            long maxTimeDifferenceMs) {
        // read parameters into a map because for HTTP POST the parameters can
        // only be read once
        Map<String, String[]> parameters = req.getParameterMap();
        boolean ok = isAuthenticated(req.getMethod(), req.getRequestURI(), parameters, keyProvider,
                maxTimeDifferenceMs);
        return new AuthenticationResult(ok, parameters);
    }

    public static boolean isAuthenticated(String verb, String requestURI,
            Map<String, String[]> parameters, KeyProvider keyProvider, long maxTimeDifferenceMs) {
        long now = System.currentTimeMillis();
        String[] hmac = parameters.get("_hmac");
        Preconditions.checkNotNull(hmac,
                "the request url should include a _hmac parameter in the request");
        Preconditions.checkArgument(hmac.length == 1,
                "there should only be one _hmac parameter in the request");
        String[] items = hmac[0].split(":");
        Preconditions.checkArgument(items.length == 2,
                "hmac parameter must be of form username:hash");
        String username = items[0];
        String signature = items[1];
        String[] timestamp = parameters.get("_timestamp");
        Preconditions.checkNotNull(timestamp,
                "the request url should include a _timestamp parameter");
        Preconditions.checkArgument(timestamp.length == 1);
        Preconditions.checkArgument(hmac.length == 1,
                "there should only be one _timestamp parameter in the request");
        byte[] key = keyProvider.getKey(username);
        return isAuthenticated(verb, requestURI, parameters, timestamp[0], signature, key, now,
                maxTimeDifferenceMs);
    }

    private static char NEW_LINE = '\n';

    public static boolean isAuthenticated(String verb, String requestURI,
            Map<String, String[]> parameters, String timestamp, String signature, byte[] key,
            long now, long maxTimeDifferenceMs) {
        if (timestampWithinWindow(timestamp, now, maxTimeDifferenceMs)) {
            String signatureInput = getSignatureInput(verb, requestURI, parameters, timestamp);
            String expectedSignature = Hmac.hmac(signatureInput, key);
            return expectedSignature.equals(signature);
        } else
            return false;
    }

    private static boolean timestampWithinWindow(String timestamp, long now,
            long maxTimeDifferenceMs) {
        ZonedDateTime time = parseTimestamp(timestamp);
        return Math.abs(time.toEpochSecond() * 1000 - now) <= maxTimeDifferenceMs;
    }

    public static String getHmacParameter(String username, byte[] key, String verb,
            String requestURI, Map<String, String[]> parameters, long timestamp) {
        String input = getSignatureInput(verb, requestURI, parameters,
                dtf.format(Instant.ofEpochMilli(timestamp)));
        return username + ":" + Hmac.hmac(input, key);
    }

    public static String getSignatureInput(String verb, String requestURI,
            Map<String, String[]> parameters, String timestamp) {

        String params = parameters.entrySet().stream()
                // sort by key
                .sorted((a, b) -> (a.getKey().compareTo(b.getKey())))
                .flatMap(entry -> Arrays.stream(entry.getValue())
                        .map(value -> entry.getKey() + "=" + value))
                .collect(Collectors.joining("\n"));

        StringBuilder b = new StringBuilder();
        b.append(verb);
        b.append(NEW_LINE);
        b.append(requestURI);
        b.append(NEW_LINE);
        b.append(params);
        b.append(NEW_LINE);
        b.append(timestamp);

        return b.toString();
    }

    private static DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME.withZone(ZoneId.of("Z"));

    static ZonedDateTime parseTimestamp(String timestamp) {
        return ZonedDateTime.parse(timestamp, dtf);
    }

}
