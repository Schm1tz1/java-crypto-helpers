package io.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class ChaCha20ProviderTest {

    public static final String ENCRYPTION_AES_IV = "encryption.aes.iv";
    final static String plainText = "Input Test Message";
    final static String password = "top$ecret!";
    final static String salt = "08154711";
    final static Logger logger = LoggerFactory.getLogger(ChaCha20ProviderTest.class);
    final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

    @Test
    void testChaChaAlgorithm() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        final String ALGO = "ChaCha20-Poly1305";

        Cipher cipher = Cipher.getInstance(ALGO);
        var keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(256);
        var key = keyGenerator.generateKey();

        byte[] nonce = new byte[12];
        var iv = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedText = cipher.doFinal(plainBytes);

        cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedText = cipher.doFinal(encryptedText);

        logger.info(plainText + " -> " + new String(encryptedText, StandardCharsets.UTF_8) + " -> " + new String(decryptedText, StandardCharsets.UTF_8));

        assertArrayEquals(plainBytes, decryptedText);
    }

}