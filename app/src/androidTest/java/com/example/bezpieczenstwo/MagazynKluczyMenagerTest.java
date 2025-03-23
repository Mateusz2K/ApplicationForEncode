package com.example.bezpieczenstwo;

import static org.junit.Assert.*;

import android.security.keystore.KeyProperties;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.util.List;

import javax.crypto.SecretKey;

@RunWith(AndroidJUnit4.class)
public class MagazynKluczyMenagerTest {

    private static final String TEST_AES_ALIAS = "testAliasAES";
    private static final String TEST_RSA_ALIAS = "testAliasRSA";

    @Before
    public void setUp() throws Exception {
        // Wyczyść KeyStore przed każdym testem
        List<String> keyAliases = MagazynKluczyMenager.getKeyAliases();
        for (String alias : keyAliases) {
            MagazynKluczyMenager.deleteKey(alias);
        }
    }

    @After
    public void tearDown() throws Exception {
        // Wyczyść KeyStore po każdym teście
        List<String> keyAliases = MagazynKluczyMenager.getKeyAliases();
        for (String alias : keyAliases) {
            MagazynKluczyMenager.deleteKey(alias);
        }
    }

    @Test
    public void createAESKey_shouldCreateAESKey() throws Exception {
        // given
        int keySize = 256;

        // when
        MagazynKluczyMenager.createAESKey(TEST_AES_ALIAS, keySize);

        // then
        SecretKey key = MagazynKluczyMenager.getAESKey(TEST_AES_ALIAS + "_AES_" + keySize);
        assertNotNull(key);
        assertEquals(keySize, key.getEncoded().length * 8);
        assertEquals(KeyProperties.KEY_ALGORITHM_AES, key.getAlgorithm());
    }

    @Test
    public void createRSAKeyPair_shouldCreateRSAKeyPair() throws Exception {
        // given
        int keySize = 2048;

        // when
        MagazynKluczyMenager.createRSAKeyPair(TEST_RSA_ALIAS, keySize);

        // then
        PublicKey publicKey = MagazynKluczyMenager.getRSAPublicKey(TEST_RSA_ALIAS + "_RSA_" + keySize);
        PrivateKey privateKey = MagazynKluczyMenager.getRSAPrivateKey(TEST_RSA_ALIAS + "_RSA_" + keySize);
        assertNotNull(publicKey);
        assertNotNull(privateKey);
        assertEquals(KeyProperties.KEY_ALGORITHM_RSA, publicKey.getAlgorithm());
        assertEquals(KeyProperties.KEY_ALGORITHM_RSA, privateKey.getAlgorithm());

    }

    @Test
    public void getAESKey_invalidAlias_shouldThrowException() {
        // when
        assertThrows(KeyStoreException.class, () -> {
            MagazynKluczyMenager.getAESKey("invalidAlias");
        });
    }

    @Test
    public void getRSAPublicKey_invalidAlias_shouldThrowException() {
        // when
        assertThrows(UnrecoverableEntryException.class, () -> {
            MagazynKluczyMenager.getRSAPublicKey("invalidAlias");
        });
    }

    @Test
    public void getRSAPrivateKey_invalidAlias_shouldThrowException() {
        // when
        assertThrows(NoSuchAlgorithmException.class, () -> {
            MagazynKluczyMenager.getRSAPrivateKey("invalidAlias");
        });
    }

    @Test
    public void encryptAndDecryptAES_shouldReturnOriginalMessage() throws Exception {
        // given
        MagazynKluczyMenager.createAESKey(TEST_AES_ALIAS, 256);
        SecretKey secretKey = MagazynKluczyMenager.getAESKey(TEST_AES_ALIAS + "_AES_256");
        String originalMessage = "This is a secret message.";

        // when
        String encryptedMessage = MagazynKluczyMenager.encryptAES(originalMessage, secretKey);
        String decryptedMessage = MagazynKluczyMenager.decryptAES(encryptedMessage, secretKey);

        // then
        assertNotEquals(originalMessage, encryptedMessage); // Zaszyfrowana wiadomość powinna być inna
        assertEquals(originalMessage, decryptedMessage); // Odszyfrowana wiadomość powinna być taka sama
    }

    @Test
    public void encryptAndDecryptRSA_shouldReturnOriginalMessage() throws Exception {
        // given
        MagazynKluczyMenager.createRSAKeyPair(TEST_RSA_ALIAS, 2048);
        PublicKey publicKey = MagazynKluczyMenager.getRSAPublicKey(TEST_RSA_ALIAS + "_RSA_2048");
        PrivateKey privateKey = MagazynKluczyMenager.getRSAPrivateKey(TEST_RSA_ALIAS + "_RSA_2048");
        String originalMessage = "This is a secret message.";

        // when
        String encryptedMessage = MagazynKluczyMenager.encryptRSA(originalMessage, publicKey);
        String decryptedMessage = MagazynKluczyMenager.decryptRSA(encryptedMessage, privateKey);

        // then
        assertNotEquals(originalMessage, encryptedMessage); // Zaszyfrowana wiadomość powinna być inna
        assertEquals(originalMessage, decryptedMessage); // Odszyfrowana wiadomość powinna być taka sama
    }

    @Test
    public void deleteKey_shouldDeleteKey() throws Exception {
        //given
        MagazynKluczyMenager.createAESKey(TEST_AES_ALIAS, 256);
        SecretKey secretKey = MagazynKluczyMenager.getAESKey(TEST_AES_ALIAS + "_AES_256");
        assertNotNull(secretKey);
        //when
        MagazynKluczyMenager.deleteKey(TEST_AES_ALIAS + "_AES_256" );
        //then
        assertThrows(KeyStoreException.class, () -> {
            MagazynKluczyMenager.getAESKey(TEST_AES_ALIAS + "_AES_256");
        });
    }

    @Test
    public void getKeyAliases_shouldReturnAllAliases() throws Exception {
        //given
        MagazynKluczyMenager.createAESKey("alias1", 256);
        MagazynKluczyMenager.createRSAKeyPair("alias2", 2048);

        //when
        List<String> keyAliases = MagazynKluczyMenager.getKeyAliases();

        //then
        assertTrue(keyAliases.contains("alias1_AES_256"));
        assertTrue(keyAliases.contains("alias2_RSA_2048"));
    }
}
