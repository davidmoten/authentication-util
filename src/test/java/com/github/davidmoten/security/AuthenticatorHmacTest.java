package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.google.common.base.Charsets;

public class AuthenticatorHmacTest {

    @Test
    public void testTimestamp() {
        ZonedDateTime t = AuthenticatorHmac.parseTimestamp("2010-01-01T00:00:00Z");
        // System.out.println(new Date(t.toInstant().toEpochMilli()));
        assertEquals(1262304000000L, t.toInstant().toEpochMilli());
        assertEquals("2010-01-01T00:00:00Z", DateTimeFormatter.ISO_DATE_TIME
                .withZone(ZoneId.of("Z")).format(Instant.ofEpochMilli(1262304000000L)));
    }

    @Test
    public void testSignature() {
        Map<String, String[]> params = createParameters();
        String input = AuthenticatorHmac.getSignatureInput("GET", "/send", params,
                "2010-01-01T00:00:00Z");
        // System.out.println(input);
        String expected = "GET\n" + "/send\n" + "a=FRED\n" + "n=123\n" + "xml=<content/>\n"
                + "2010-01-01T00:00:00Z";
        assertEquals(expected, input);
    }

    @Test
    public void testHmac() {
        String hmac = AuthenticatorHmac.getHmacParameter("johnno", "thing".getBytes(Charsets.UTF_8),
                "GET", "/send", createParameters(), 1262304000000L);
        assertEquals("johnno:fLfZuEkQnl3FWf1DQaZbT6Gmfas=", hmac);
    }

    private static Map<String, String[]> createParameters() {
        Map<String, String[]> params = new HashMap<String, String[]>();
        params.put("xml", new String[] { "<content/>" });
        params.put("n", new String[] { "123" });
        params.put("a", new String[] { "FRED" });
        return params;
    }

}
