package io.kowalski.stronghold;

import javax.crypto.SecretKey;

import io.kowalski.stronghold.crypto.AESKeyTool;
import io.kowalski.stronghold.crypto.Secret;

public class App {

    public static void main(final String[] args) {

        final AESKeyTool keytool = new AESKeyTool();
        final SecretKey key = keytool.generateKey("brandon".toCharArray());

        final Secret secret = keytool.encrypt(key, "Brandon is a towel");

        final String decrypted = (String) keytool.decrypt(key, secret);

        System.out.println(decrypted);

    }

}
