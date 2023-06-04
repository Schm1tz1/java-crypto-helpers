package com.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesHelperTest {

    final static String plainText = "Input Test Message";
    final byte[] plainBytes = "Input Bytes".getBytes(StandardCharsets.UTF_8);
    final static String password = "top$ecret!";
    final static String salt = "08154711";

    @Test
    void AESEncryptDecryptAesEcbPasswordByteArray() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedBytes = AesHelper.encrypt(AesHelper.AES_ECB, plainBytes, key, null);
        var decryptedBytes = AesHelper.decrypt(AesHelper.AES_ECB, encryptedBytes, key, null);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + Arrays.toString(encryptedBytes) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesCbcPasswordByteArray() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var iv = AesHelper.randomIv(16);
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedBytes = AesHelper.encrypt(AesHelper.AES_CBC, plainBytes, key, iv);
        var decryptedBytes = AesHelper.decrypt(AesHelper.AES_CBC, encryptedBytes, key, iv);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + new String(encryptedBytes, StandardCharsets.UTF_8) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesGcmPasswordByteArray() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // NIST recommendation for GCM: 12 bits IV + 4 counter
        // (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
        var iv = AesHelper.randomIv(12);
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedBytes = AesHelper.encrypt(AesHelper.AES_GCM, plainBytes, key, iv);
        var decryptedBytes = AesHelper.decrypt(AesHelper.AES_GCM, encryptedBytes, key, iv);
        System.out.println("  " + new String(plainBytes, StandardCharsets.UTF_8) + "->" + new String(encryptedBytes, StandardCharsets.UTF_8) + "->" + new String(decryptedBytes, StandardCharsets.UTF_8));
        assertArrayEquals(plainBytes, decryptedBytes);
    }

    @Test
    void AESEncryptDecryptAesEcbPasswordStringMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedText = AesHelper.encryptToString(AesHelper.AES_ECB, plainText, key, null);
        var decryptedText = AesHelper.decryptString(AesHelper.AES_ECB, encryptedText, key, null);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void AESEncryptDecryptAesCbcPasswordStringMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        var iv = AesHelper.randomIv(16);
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedText = AesHelper.encryptToString(AesHelper.AES_CBC, plainText, key, iv);
        var decryptedText = AesHelper.decryptString(AesHelper.AES_CBC, encryptedText, key, iv);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void AESEncryptDecryptAesGcmPasswordStringMessage() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // NIST recommendation for GCM: 12 bits IV + 4 counter
        // (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
        var iv = AesHelper.randomIv(12);
        var key = AesHelper.getKeyFromPassword(password, salt);

        var encryptedText = AesHelper.encryptToString(AesHelper.AES_GCM, plainText, key, iv);
        var decryptedText = AesHelper.decryptString(AesHelper.AES_GCM, encryptedText, key, iv);
        System.out.println("  " + plainText + "->" + encryptedText + "->" + decryptedText);
        assertEquals(plainText, decryptedText);
    }
}