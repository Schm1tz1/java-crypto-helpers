package io.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AesProviderTest {

    public static final String ENCRYPTION_AES_IV = "encryption.aes.iv";
    final static String plainText = "Input Test Message";
    final static String password = "top$ecret!";
    final static String salt = "08154711";
    final static Logger logger = LoggerFactory.getLogger(AesProviderTest.class);
    final byte[] plainBytes = "Input Bytes".getBytes(StandardCharsets.UTF_8);

    @Test
    void AESEncryptDecryptAesEcbPasswordByteArray() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedBytes = AesProvider.encrypt(AesProvider.AES_ECB, plainBytes, key, null);
        var decryptedBytes = AesProvider.decrypt(AesProvider.AES_ECB, encryptedBytes, key, null);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + Arrays.toString(encryptedBytes) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesCbcPasswordByteArray() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var iv = AesProvider.randomIv(16);
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedBytes = AesProvider.encrypt(AesProvider.AES_CBC, plainBytes, key, iv);
        var decryptedBytes = AesProvider.decrypt(AesProvider.AES_CBC, encryptedBytes, key, iv);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + new String(encryptedBytes, StandardCharsets.UTF_8) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesGcmPasswordByteArray() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // NIST recommendation for GCM: 12 bits IV + 4 counter
        // (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
        var iv = AesProvider.randomIv(12);
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedBytes = AesProvider.encrypt(AesProvider.AES_GCM, plainBytes, key, iv);
        var decryptedBytes = AesProvider.decrypt(AesProvider.AES_GCM, encryptedBytes, key, iv);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + new String(encryptedBytes, StandardCharsets.UTF_8) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesEcbPasswordStringMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedText = AesProvider.encryptToString(AesProvider.AES_ECB, plainText, key, null);
        var decryptedText = AesProvider.decryptString(AesProvider.AES_ECB, encryptedText, key, null);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void AESEncryptDecryptAesCbcPasswordStringMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var iv = AesProvider.randomIv(16);
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedText = AesProvider.encryptToString(AesProvider.AES_CBC, plainText, key, iv);
        var decryptedText = AesProvider.decryptString(AesProvider.AES_CBC, encryptedText, key, iv);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void AESEncryptDecryptAesGcmPasswordStringMessage() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // NIST recommendation for GCM: 12 bits IV + 4 counter
        // (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
        var iv = AesProvider.randomIv(12);
        var key = AesProvider.getKeyFromPassword(password, salt);

        var encryptedText = AesProvider.encryptToString(AesProvider.AES_GCM, plainText, key, iv);
        var decryptedText = AesProvider.decryptString(AesProvider.AES_GCM, encryptedText, key, iv);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void testHelperFullyConfigured() throws NoSuchAlgorithmException {

        var randomKey = AesProvider.generateKey(256);
        var randomKeyBase64Encoded = Base64.getEncoder().encodeToString(randomKey.getEncoded());
        logger.info("New 256bit key generated: " + randomKeyBase64Encoded);

        final Map<String, Object> props = new HashMap<>();
        props.put(CryptoProvider.ENCRYPTION_KEY, randomKeyBase64Encoded);
        props.put(CryptoProvider.ALGORITHM_PARAMETERS, AesProvider.AES_GCM);
        props.put(AesProvider.INITIALIZATION_VECTOR, "ABCDE08154711");

        var aesHelper = new AesProvider();
        aesHelper.configure(props);

        byte[] plaintextAsBytes = "Test-String".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextAsBytes = aesHelper.encrypt(plaintextAsBytes);
        assertNotNull(aesHelper.encrypt(plaintextAsBytes));

        logger.info(new String(ciphertextAsBytes, StandardCharsets.UTF_8));
    }

}