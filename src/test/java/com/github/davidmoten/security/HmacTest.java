package com.github.davidmoten.security;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class HmacTest {

    @Test
    public void testHmacFromQuickHashDotCom() {
        String expected = "xogelEsPGeLhlW7zuPzefAZCpDY=";
        String hmac = Hmac.hmac("the quick brown fox jumps over the lazy dog", "key");
        assertEquals(expected, hmac);
    }

    @Test
    public void testHmacFromQuickHashDotComEmptyString() {
        String expected = "9Cuw7rAY671Fl65yE3EexgdghD8=";
        String hmac = Hmac.hmac("", "key");
        assertEquals(expected, hmac);
    }

}
