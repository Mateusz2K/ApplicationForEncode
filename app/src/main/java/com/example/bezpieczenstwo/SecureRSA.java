package com.example.bezpieczenstwo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
//szyfrowanie symetryczne
public class SecureRSA {
    private final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    private final KeyPair keyPair;
    private final PublicKey publicKey;
    private static PrivateKey privateKey;

    public SecureRSA(int keySize) throws Exception {
        keyGenerator.initialize(keySize);
        keyPair = keyGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encData));
        return new String(decryptedBytes);
    }

    public static String decrypt(String encData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encData));
        return new String(decryptedBytes);
    }
}
