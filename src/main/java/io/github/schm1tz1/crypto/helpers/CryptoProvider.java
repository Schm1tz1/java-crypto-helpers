package io.github.schm1tz1.crypto.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

public abstract class CryptoProvider {

    public static final String ENCRYPTION_KEY = "encryption.key";
    public static final String ALGORITHM_PARAMETERS = "encryption.cipher.mode";
    public static final String BASE64_OUTPUT = "encryption.output.base64";
    private static final Logger log = LoggerFactory.getLogger(CryptoProvider.class);
    protected Boolean encodeBase64;
    protected String algorithmParameters;

    public abstract byte[] encrypt(byte[] plaintextIn);

    public String encrypt(String plaintextIn) {
        return new String(encrypt(plaintextIn.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    public abstract byte[] decrypt(byte[] ciphertextIn);

    public void configure(Map<String, ?> configs) {
        final var algorithmParameters = (String) configs.get(ALGORITHM_PARAMETERS);
        this.algorithmParameters = algorithmParameters;
        log.info("Setting algorithm parameters to " + this.algorithmParameters);


        final var encodeBase64 = (Boolean) configs.get(BASE64_OUTPUT);
        this.encodeBase64 = Objects.requireNonNullElse(encodeBase64, false);
        log.info("Base64 encoded output: " + this.encodeBase64.toString());

    }

    public String decrypt(String ciphertextIn) {
        return new String(decrypt(ciphertextIn.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

}
