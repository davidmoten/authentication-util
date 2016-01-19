package com.github.davidmoten.servlet.security;

import java.io.IOException;
import java.util.function.Supplier;

import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.github.davidmoten.security.Hmac;
import com.google.common.base.Charsets;
import com.google.common.io.ByteStreams;

public final class AwsS3Authentication {

    public static boolean isAuthorized(String username, String password, AmazonS3Client s3,
            String bucket, Supplier<String> passwordHashKey) {
        String passwordHash;
        try (S3ObjectInputStream stream = s3.getObject(bucket, username + ".hash")
                .getObjectContent()) {
            passwordHash = new String(ByteStreams.toByteArray(stream), Charsets.UTF_8).trim();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String salt;
        try (S3ObjectInputStream stream = s3.getObject(bucket, username + ".salt")
                .getObjectContent()) {
            salt = new String(ByteStreams.toByteArray(stream), Charsets.UTF_8).trim();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String calculatedPasswordHash = Hmac.hmac(password + salt, passwordHashKey.get());
        return passwordHash.equals(calculatedPasswordHash);
    }

}
