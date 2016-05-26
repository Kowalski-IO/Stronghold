package io.kowalski.stronghold.crypto;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.SerializationUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AESKeyTool implements KeyTool {

    private static final String FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHM = "AES";
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;

    // Bypass JVM Crypto Restrictions
    static {
        try {
            final Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);
            field.set(null, java.lang.Boolean.FALSE);
        } catch (final Exception e) {
            log.error("Unable to bypass JVM restriction", e);
        }
    }

    @Override
    public SecretKey generateKey(final char[] password) {

        SecretKey secretKey = null;
        try {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_ALGORITHM);
            final Random r = new SecureRandom();

            final byte[] salt = new byte[32];
            r.nextBytes(salt);

            final KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
            final SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

        } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return secretKey;
    }

    @Override
    public String encodeKey(final SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Override
    public SecretKey decodeKey(final String encodedKey) {
        final byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    @Override
    public Secret encrypt(final SecretKey key, final Serializable payload) {
        Secret secret = null;
        try {
            final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);

            final byte[] iv = new byte[16];
            final SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

            final byte[] cipherText = cipher.doFinal(SerializationUtils.serialize(payload));

            secret = new Secret(iv, cipherText);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return secret;
    }

    @Override
    public Serializable decrypt(final SecretKey key, final Secret secret) {

        Serializable payload = null;

        try {
            final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);

            final IvParameterSpec ivParameterSpec = new IvParameterSpec(secret.getIv());
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

            final byte[] plainText = cipher.doFinal(secret.getCipherText());

            payload = SerializationUtils.deserialize(plainText);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return payload;
    }

}
