package io.kowalski.stronghold.crypto;

import java.io.Serializable;

import javax.crypto.SecretKey;

public interface KeyTool {

    SecretKey generateKey(char[] password);

    String encodeKey(SecretKey key);

    SecretKey decodeKey(String encodedKey);

    Secret encrypt(SecretKey key, Serializable payload);

    Serializable decrypt(SecretKey key, Secret secret);

}
