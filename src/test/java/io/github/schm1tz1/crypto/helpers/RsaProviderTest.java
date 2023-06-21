package io.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RsaProviderTest {

    final static Logger logger = LoggerFactory.getLogger(RsaProviderTest.class);
    private static final String TEST_STRING = "2019-03-04T15:02:37.2586600+01:00";

    @Test
    void testXmlKeyParsingPublicKey() {
        String examplePubKey = "<RSAKeyValue><Modulus>iX9gRAHRSFheYPXs0Awb+kVSC2kkcY624EDSZbIx+InQ+LsXDMu0D7GwOQX8mn/t7rs9f"
                + "j6m3uqJxmtj7m14IN4QEaaDS00je7FNJs3KtMtERlKg5rC8+xikMQe0QH+MJzepwEL6fxNYv4gIENg0UTPFgISJdL9A"
                + "uXIKCS58FLZFmgVmER7edH8dLRE0bgA9EnHuOWb41E/PhXe+Wqnxt0qpoKgsHNqvgXXWY7GB6JJmsesxca/5/7buMWU"
                + "b1hjlm1Ro20Ntdh0pRJDx8HqlUOBJ1Lgp5E4bKa5NeY9KlES/5tI2cNKUXjyy+hFNaG3w8E3zWwW9i3p8t3zw5rPt4Q"
                + "==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        HashMap<String, BigInteger> pubKeyAsMap = RsaProvider.XmlKeyParser.parseKeyFromXmlString(examplePubKey);
        logger.info(pubKeyAsMap.toString());

        assertNotNull(pubKeyAsMap.get("Modulus"));
        assertNotNull(pubKeyAsMap.get("Exponent"));
    }

    @Test
    void testXmlKeyParsingPrivateKey() {
        String examplePrivateKey = "<RSAKeyValue><Modulus>iDedXXkixunqnh278qUll8sWYIqyy/FfTd59kq6HDwXDapOXmYKkcsy+HTFbbLRb/bbJsMVEessdbwEVysedzx38QnWOBmGmY1VTKO8Ph3X1dkVktMT8zCbgKMBBT17dTbBE+B9zO6jqcN120qaHc8rOGC2KztM5xnEa3hNvSwk="
                + "</Modulus><Exponent>AQAB"
                + "</Exponent><P>1TmBWEl5DARzhcmaaLJELymx0Sw3xcdEqEi/2nnIYrLE1YCb0OQVHvyFBBnXEgk81zxoqkPmItNO1yHzX7UIzw=="
                + "</P><Q>o4tFYK9HE4UhaLUGzx9WpFlX8NXsXcYxzV2ewCR1EXaMCA8xowSyyDfzhUugfKI02rTeQRucTnuttbJEQsu0pw=="
                + "</Q><DP>IKzGSHxB43iPJ3JkiiS/VCbki/Rlu5Y0zEERvW4qKg3RIhKqThGVtwDldWJsVeQ6gZVNSMJM8wtEqq0WOZVpew=="
                + "</DP><DQ>UAn3GExwEqOTKDWAcZm6w5BeM6Xemj5HXWS2Lv8otDU6by9QcaH5BXgsnE3Y62ZPS8I9C8xBgT+SUlw+gBpF/Q=="
                + "</DQ><InverseQ>lbcDsYsWBNg365eRqp8n8sGLR5gdG+SV5YUAZY+Bf1P2V9cpIm8YpVcUKZXkE5SwGub7p+mCQkAbaoT/pQyXOg=="
                + "</InverseQ><D>fi82wa5DfwyV4J8eymod5v2k3w3dD3urk5D1tnmid1IZcpMCrpwNBqOPwa9FR+/T/7XiJLS4+R9LRtc0fsJn9maEfUV26ry3vqQXYRlobdsWMFuNZPmHD1S7ef1fkGthDGWMmdiKyyy5Cy+lXEM/9VlexSKMxZc3Tor+v5SCB/k="
                + "</D></RSAKeyValue>";

        HashMap<String, BigInteger> pubKeyAsMap = RsaProvider.XmlKeyParser.parseKeyFromXmlString(examplePrivateKey);
        logger.info(pubKeyAsMap.toString());

        assertNotNull(pubKeyAsMap.get("Modulus"));
        assertNotNull(pubKeyAsMap.get("Exponent"));
        assertNotNull(pubKeyAsMap.get("D"));
        assertNotNull(pubKeyAsMap.get("P"));
        assertNotNull(pubKeyAsMap.get("Q"));
        assertNotNull(pubKeyAsMap.get("DP"));
        assertNotNull(pubKeyAsMap.get("DQ"));
        assertNotNull(pubKeyAsMap.get("InverseQ"));
    }

    @Test
    void testModulusExponentToKeyConversion() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {

        HashMap<String, BigInteger> pubKeyAsMap = createTestPubKeyAsMap();
        PublicKey pubKey = RsaProvider.createPublicKey(pubKeyAsMap);
        assertEquals("X.509", pubKey.getFormat());

        logger.info(pubKey.toString());
        logger.info("-----BEGIN PUBLIC KEY-----");
        logger.info(Base64.getEncoder().encodeToString(pubKey.getEncoded()));
        logger.info("-----END PUBLIC KEY-----");

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] cipherData = cipher.doFinal(TEST_STRING.getBytes("UTF-8"));
        String encrypted = Base64.getEncoder().encodeToString(cipherData);
        logger.info("Encrypted message: " + encrypted);
    }

    @Test
    void testPemToPubKeyConversion() throws IOException {
        var testKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T" +
                "JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK" +
                "wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU" +
                "NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH" +
                "A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ" +
                "Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG" +
                "QQIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        var finalPubKey = RsaProvider.parsePemToRsaPubKey(testKey);
        logger.info(finalPubKey.toString());
        logger.info(Base64.getEncoder().encodeToString(finalPubKey.getEncoded()));

        assert testKey.contains(Base64.getEncoder().encodeToString(finalPubKey.getEncoded()));
    }

    @Test
    void testRsaKeyFormatDetection() {
        var testKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T" +
                "JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK" +
                "wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU" +
                "NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH" +
                "A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ" +
                "Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG" +
                "QQIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        var testKeyXml = "<RSAKeyValue><Modulus>iX9gRAHRSFheYPXs0Awb+kVSC2kkcY624EDSZbIx+InQ+LsXDMu0D7GwOQX8mn/t7rs9f"
                + "j6m3uqJxmtj7m14IN4QEaaDS00je7FNJs3KtMtERlKg5rC8+xikMQe0QH+MJzepwEL6fxNYv4gIENg0UTPFgISJdL9A"
                + "uXIKCS58FLZFmgVmER7edH8dLRE0bgA9EnHuOWb41E/PhXe+Wqnxt0qpoKgsHNqvgXXWY7GB6JJmsesxca/5/7buMWU"
                + "b1hjlm1Ro20Ntdh0pRJDx8HqlUOBJ1Lgp5E4bKa5NeY9KlES/5tI2cNKUXjyy+hFNaG3w8E3zWwW9i3p8t3zw5rPt4Q"
                + "==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        assertTrue(RsaProvider.isPemKeyFormat(testKeyPem));
        assertFalse(RsaProvider.isPemKeyFormat(testKeyXml));
    }

    @Test
    void testHelperFullyConfigured() {

        String examplePubKey = "<RSAKeyValue><Modulus>iX9gRAHRSFheYPXs0Awb+kVSC2kkcY624EDSZbIx+InQ+LsXDMu0D7GwOQX8mn/t7rs9f"
                + "j6m3uqJxmtj7m14IN4QEaaDS00je7FNJs3KtMtERlKg5rC8+xikMQe0QH+MJzepwEL6fxNYv4gIENg0UTPFgISJdL9A"
                + "uXIKCS58FLZFmgVmER7edH8dLRE0bgA9EnHuOWb41E/PhXe+Wqnxt0qpoKgsHNqvgXXWY7GB6JJmsesxca/5/7buMWU"
                + "b1hjlm1Ro20Ntdh0pRJDx8HqlUOBJ1Lgp5E4bKa5NeY9KlES/5tI2cNKUXjyy+hFNaG3w8E3zWwW9i3p8t3zw5rPt4Q"
                + "==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        final Map<String, Object> props = new HashMap<>();
        props.put(CryptoProvider.ENCRYPTION_KEY, examplePubKey);
        props.put(CryptoProvider.ALGORITHM_PARAMETERS, RsaProvider.RSA_OAEP);

        var rsaHelper = new RsaProvider();
        rsaHelper.configure(props);

        byte[] plaintextAsBytes = "Test-String".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextAsBytes = rsaHelper.encrypt(plaintextAsBytes);
        assertNotNull(rsaHelper.encrypt(plaintextAsBytes));
        logger.info(new String(ciphertextAsBytes, StandardCharsets.UTF_8));
    }

    private HashMap<String, BigInteger> createTestPubKeyAsMap() {
        var pubKeyAsMap = new HashMap<String, BigInteger>();
        byte[] mod = Base64.getDecoder().decode("iX9gRAHRSFheYPXs0Awb+kVSC2kkcY624EDSZbIx+InQ+LsXDMu0D7GwOQX8mn/t7rs9fj6m3uqJxmtj7m14IN4QEaaDS00je7FNJs3KtMtERlKg5rC8+xikMQe0QH+MJzepwEL6fxNYv4gIENg0UTPFgISJdL9AuXIKCS58FLZFmgVmER7edH8dLRE0bgA9EnHuOWb41E/PhXe+Wqnxt0qpoKgsHNqvgXXWY7GB6JJmsesxca/5/7buMWUb1hjlm1Ro20Ntdh0pRJDx8HqlUOBJ1Lgp5E4bKa5NeY9KlES/5tI2cNKUXjyy+hFNaG3w8E3zWwW9i3p8t3zw5rPt4Q==");
        byte[] exp = Base64.getDecoder().decode("AQAB");

        pubKeyAsMap.put("Modulus", new BigInteger(1, mod));
        pubKeyAsMap.put("Exponent", new BigInteger(1, exp));
        return pubKeyAsMap;
    }

}