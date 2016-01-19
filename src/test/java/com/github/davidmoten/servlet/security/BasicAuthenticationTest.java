package com.github.davidmoten.servlet.security;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.amazonaws.util.Base64;
import com.google.common.base.Charsets;

public final class BasicAuthenticationTest {

    @Test
    public void testCreate() {
        BasicAuthentication u = BasicAuthentication.create("a", "b");
        assertEquals("a", u.username());
        assertEquals("b", u.password());
    }

    @Test
    public void testParse() {
        BasicAuthentication u = BasicAuthentication.from("Authorization: Basic "
                + Base64.encodeAsString("user:pass".getBytes(Charsets.UTF_8)));
        assertEquals("user", u.username());
        assertEquals("pass", u.password());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseWithWrongHeaderReturnsException() {
        BasicAuthentication u = BasicAuthentication.from("Authorizationzzzz: Basic "
                + Base64.encodeAsString("user:pass".getBytes(Charsets.UTF_8)));
        assertEquals("user", u.username());
        assertEquals("pass", u.password());
    }

    @Test(expected = NullPointerException.class)
    public void testParseOfNullThrowsNullPointerException() {
        BasicAuthentication.from((String) null);
    }

}
