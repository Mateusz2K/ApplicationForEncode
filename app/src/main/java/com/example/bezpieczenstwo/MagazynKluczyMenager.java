package com.example.bezpieczenstwo;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MagazynKluczyMenager {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String AES_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String RSA_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
    private static final String BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;
    private static final String BLOCK_MODE_ECB = KeyProperties.BLOCK_MODE_ECB;
    private static final String PADDING_AES = KeyProperties.ENCRYPTION_PADDING_PKCS7;
    private static final String PADDING_RSA = KeyProperties.ENCRYPTION_PADDING_RSA_OAEP;
    private static final String TRANSFORMATION_AES = AES_ALGORITHM + "/" + BLOCK_MODE + "/" + PADDING_AES;
    private static final String TRANSFORMATION_RSA =RSA_ALGORITHM + "/" + BLOCK_MODE_ECB + "/" + PADDING_RSA ;

    private static KeyStore keyStore;

    static {
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e("MagazynKluczyMenager", "Błąd inicjalizacji KeyStore", e);
        }
    }

    // Metody dla kluczy AES
    public static void createAESKey(String keyAlias, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM, KEYSTORE_PROVIDER);
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias + "_" + "AES" + "_" + keySize, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING_AES)
                .setKeySize(keySize)
                .build();
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    public static SecretKey getAESKey(String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (SecretKey) keyStore.getKey(keyAlias, null);
    }

    // Metody dla kluczy RSA
    public static void createRSAKeyPair(String keyAlias, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM, KEYSTORE_PROVIDER);
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias + "_" + "RSA" + "_" + keySize, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(keySize)
                .setEncryptionPaddings(PADDING_RSA)
                .build();
        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();
        System.out.println("Klucz RSA: "+keyAlias+" został utworzony");
    }

    public static PublicKey getRSAPublicKey(String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        Certificate certificate = keyStore.getCertificate(keyAlias);
        if (certificate != null) {
            return certificate.getPublicKey();
        } else {
            throw new KeyStoreException("Nie znaleziono klucza publicznego dla aliasu: " + keyAlias);
        }
    }

    public static PrivateKey getRSAPrivateKey(String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Key key = keyStore.getKey(keyAlias, null);
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new KeyStoreException("Nie znaleziono klucza prywatnego dla aliasu: " + keyAlias);
        }
    }

    public static String encryptAES(String message, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES);
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Łączenie IV i zaszyfrowanych danych w Base64
            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Błąd szyfrowania AES", e);
        }
    }

    public static String decryptAES(String encryptedMessage, SecretKey secretKey) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES);
            byte[] combined = Base64.getDecoder().decode(encryptedMessage);

            // Odczytanie IV (pierwsze 16 bajtów)
            byte[] iv = new byte[16];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Odczytanie zaszyfrowanej wiadomości
            byte[] encryptedBytes = new byte[combined.length - iv.length];
            System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Błąd deszyfrowania AES", e);
        }
    }

    public static String encryptRSA(String message, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (RuntimeException e) {
            throw new RuntimeException("Błąd szyfrowania RSA", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptRSA(String encryptedMessage, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Błąd deszyfrowania RSA", e);
        }
    }

    public static List<String> getKeyAliases() {
        List<String> aliases = new ArrayList<>();
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null); // Ładowanie KeyStore
            Enumeration<String> enumeration = keyStore.aliases(); // Pobranie enumeracji aliasów

            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                aliases.add(alias);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            Log.e("KeyStoreManager", "Error listing aliases", e);
        }
        return aliases;
    }
    public static void deleteKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null); // Ładowanie KeyStore
            if (keyStore.containsAlias(alias)) { // Sprawdzenie, czy alias istnieje
                keyStore.deleteEntry(alias);
                // Usuwanie wpisu (klucza)
                Log.d("KeyStoreManager", "Key with alias '" + alias + "' deleted successfully.");
            } else {
                Log.w("KeyStoreManager", "Key with alias '" + alias + "' not found.");
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            Log.e("KeyStoreManager", "Error deleting key with alias '" + alias + "'", e);
        }
    }

}
