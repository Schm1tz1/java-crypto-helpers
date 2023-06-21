package io.github.schm1tz1.crypto.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Helper Class for RSA-based Asymmetric Cryptography
 */
public class RsaProvider extends CryptoProvider {

    public static final String RSA_OAEP = "RSA/ECB/OAEPPadding";
    public static final String RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
    public static final String RSA_OAEP_SHA256_MGF1 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final Logger log = LoggerFactory.getLogger(RsaProvider.class);
    private PublicKey publicKey;

    public RsaProvider() {
    }

    static PublicKey createPublicKey(HashMap<String, BigInteger> keySpecs) {
        PublicKey pubKey = null;
        try {
            pubKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(keySpecs.get("Modulus"), keySpecs.get("Exponent")));
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        return pubKey;
    }

    static PrivateKey createPrivateKey(HashMap<String, BigInteger> keySpecs) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(keySpecs.get("Modulus"), keySpecs.get("Exponent"), keySpecs.get("D"), keySpecs.get("P"), keySpecs.get("Q"), keySpecs.get("DP"), keySpecs.get("DQ"), keySpecs.get("InverseQ")));

        return privateKey;
    }

    static PublicKey parsePemToRsaPubKey(String keyAsPem) {
        String keyContents = keyAsPem.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(keyContents);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    static boolean isPemKeyFormat(String keyAsString) {
        return keyAsString.startsWith("-----BEGIN PUBLIC KEY-----") || keyAsString.startsWith("MII");
    }

    @Override
    public byte[] encrypt(byte[] plaintextIn) {
        byte[] cipherData;
        try {
            Cipher cipher = Cipher.getInstance(this.algorithmParameters);
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

            cipherData = cipher.doFinal(plaintextIn);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        String encrypted = Base64.getEncoder().encodeToString(cipherData);
        return encrypted.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(byte[] ciphertextIn) {
        return null;
    }

    @Override
    public void configure(Map<String, ?> configs) {
        super.configure(configs);

        final var keyAsString = (String) configs.get(ENCRYPTION_KEY);

        if (isPemKeyFormat(keyAsString)) {
            log.info("Processing PEM encoded public RSA key...");
            this.publicKey = parsePemToRsaPubKey(keyAsString);
        } else {
            log.info("Processing XML encoded public RSA key...");
            var parsedXmlKeyAsMap = XmlKeyParser.parseKeyFromXmlString(keyAsString);
            this.publicKey = createPublicKey(parsedXmlKeyAsMap);
        }

    }

    class XmlKeyParser {
        static HashMap<String, BigInteger> parseKeyFromXmlString(String xmlInput) {
            DocumentBuilder db = null;
            try {
                db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            } catch (ParserConfigurationException e) {
                throw new RuntimeException("Error setting up XML parser: ", e);
            }
            Element elementsByTagName = null;
            try {
                elementsByTagName = db.parse(new ByteArrayInputStream(xmlInput.getBytes())).getDocumentElement();
            } catch (SAXException e) {
                throw new RuntimeException("Cannot parse XML input: ", e);
            } catch (IOException e) {
                throw new RuntimeException("Cannot read input: ", e);
            }

            String[] names = {"Modulus", "Exponent", "D", "P", "Q", "DP", "DQ", "InverseQ"};

            var values = new HashMap<String, BigInteger>();
            Element finalElementsByTagName = elementsByTagName;
            Arrays.stream(names).sequential().forEach(key -> {
                var firstItem = finalElementsByTagName.getElementsByTagName(key).item(0);
                if (Objects.isNull(firstItem)) {
                    return;
                }
                var value = firstItem.getTextContent();
                if (value != null) {
                    var parsedValue = new BigInteger(1, Base64.getDecoder().decode(value));
                    values.put(key, parsedValue);
                }
            });
            return values;
        }
    }

}
