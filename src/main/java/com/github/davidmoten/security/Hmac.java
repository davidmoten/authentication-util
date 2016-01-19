package com.github.davidmoten.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Charsets;

/**
 * Common routines for generating authentication signatures for AWS requests.
 */
public final class Hmac {

    private Hmac() {
        // prevent instantiation
    }

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    /**
     * Returns RFC 2104-compliant HMAC signature using given data and key.
     * 
     * @param data
     *            The data to be signed
     * @param key
     *            The signing key
     * @return The Base64-encoded RFC 2104-compliant HMAC signature
     */
    public static String hmac(byte[] data, byte[] key) {
        try {
            // get an hmac_sha1 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
            // get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);
            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data);
            // base64-encode the hmac
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String hmac(String data, String key) {
        return hmac(data.getBytes(Charsets.UTF_8), key.getBytes(Charsets.UTF_8));
    }

    public static String hmac(String data, byte[] key) {
        return hmac(data.getBytes(Charsets.UTF_8), key);
    }

    public static String hmac(byte[] data, String key) {
        return hmac(data, key.getBytes(Charsets.UTF_8));
    }
}
