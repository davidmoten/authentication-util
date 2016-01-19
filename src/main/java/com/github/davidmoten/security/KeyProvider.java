package com.github.davidmoten.security;

public interface KeyProvider {
    byte[] getKey(String name);
}
