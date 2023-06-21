package io.github.schm1tz1.crypto.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

public abstract class CryptoProvider {

    public static final String ENCRYPTION_KEY = "encryption.key";
    public static final String ALGORITHM_PARAMETERS = "encryption.cipher.mode";
    public static final String STRINGS_USE_BASE_64 = "encryption.strings.use.base64";
    private static final Logger log = LoggerFactory.getLogger(CryptoProvider.class);
    protected Boolean stringsAsBase64;
    protected String algorithmParameters;

    public abstract byte[] encrypt(byte[] plaintextIn);

    public String encrypt(String plaintextIn) {
        var cipherData = encrypt(plaintextIn.getBytes(StandardCharsets.UTF_8));
        if (stringsAsBase64) {
            return Base64.getEncoder().encodeToString(cipherData);
        }
        return new String(cipherData, StandardCharsets.UTF_8);
    }

    public abstract byte[] decrypt(byte[] ciphertextIn);

    public void configure(Map<String, ?> configs) {
        final var algorithmParameters = (String) configs.get(ALGORITHM_PARAMETERS);
        this.algorithmParameters = algorithmParameters;
        log.info("Setting algorithm parameters to " + this.algorithmParameters);


        final var stringsAsBase64 = (Boolean) configs.get(STRINGS_USE_BASE_64);
        this.stringsAsBase64 = Objects.requireNonNullElse(stringsAsBase64, true);
        log.info("Base64 encoded output: " + this.stringsAsBase64.toString());

    }

    public String decrypt(String ciphertextIn) {
        var ciphertextBytes = stringToBytes(ciphertextIn);
        return new String(decrypt(ciphertextBytes), StandardCharsets.UTF_8);
    }

    byte[] stringToBytes(String inputString) {
        if (stringsAsBase64) {
            return Base64.getDecoder().decode(inputString);
        }
        return inputString.getBytes(StandardCharsets.UTF_8);
    }

    String bytesToString(byte[] inputBytes) {
        if (stringsAsBase64) {
            return Base64.getEncoder().encodeToString(inputBytes);
        }
        return new String(inputBytes, StandardCharsets.UTF_8);
    }

}
