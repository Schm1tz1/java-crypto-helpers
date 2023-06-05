package io.github.schm1tz1.crypto.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AesHelper {

    public static final String AES_ECB = "AES/ECB/PKCS5PADDING";
    public static final String AES_CBC = "AES/CBC/PKCS5PADDING";
    public static final String AES_GCM = "AES/GCM/NoPadding";
    private static final Logger log = LoggerFactory.getLogger(AesHelper.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String encryptToString(String algorithm, String input, Key key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        var inputBytes = input.getBytes(StandardCharsets.UTF_8);
        var cipherText = encrypt(algorithm, inputBytes, (SecretKey) key, iv);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static byte[] encrypt(String algorithm, byte[] inputBytes, Key key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance(algorithm);

        if (iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else if (AES_GCM.equalsIgnoreCase(algorithm)) {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }

        return cipher.doFinal(inputBytes);
    }

    public static String decryptString(String algorithm, String cipherText, Key key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        var bytes = Base64.getDecoder().decode(cipherText);
        var plainText = decrypt(algorithm, bytes, (SecretKey) key, iv);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static byte[] decrypt(String algorithm, byte[] inputBytes, Key key) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return decrypt(algorithm, inputBytes, key, null);
    }

    public static byte[] decrypt(String algorithm, byte[] inputBytes, Key key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {

        var cipher = Cipher.getInstance(algorithm);

        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else if (AES_GCM.equalsIgnoreCase(algorithm)) {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }

        return cipher.doFinal(inputBytes);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static byte[] randomIv(int length) {
        var iv = new byte[length];
        secureRandom.nextBytes(iv);
        return iv;
    }


}
