package io.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RsaHelperTest {

    final static Logger logger = LoggerFactory.getLogger(RsaHelperTest.class);
    private static final String TEST_STRING = "Hello World!";


    @Test
    void testBase64Processing() {
        var testValueNoSpecialChars = RsaHelper.XmlKeyParser.parseEncodedBigInteger("AQAB");
        var testValueTabs = RsaHelper.XmlKeyParser.parseEncodedBigInteger("AQ\tAB");
        var testValueNewlines = RsaHelper.XmlKeyParser.parseEncodedBigInteger("AQ\nAB");

        assertEquals(BigInteger.valueOf(65537), testValueNoSpecialChars);
        assertEquals(BigInteger.valueOf(65537), testValueTabs);
        assertEquals(BigInteger.valueOf(65537), testValueNewlines);
    }

    @Test
    void testXmlKeyParsingPublicKey() {
        String examplePubKey = "<RSAKeyValue><Modulus>xs1GwyPre7/knVd3CAO1pyk++yp/qmBz2TekgrehYT\n" +
                "WU7hs8bUCeVQrL2OB+jm/AgjdPMohWHD/tLcJy35aZgVfPI3Oa3gmXxdoLZrfNRb\n" +
                "nrCm3Xr1MR7wnhMyBt5XXyU/FiF46g5qJ2DUIUg7teoKDNUSAN81JTIoH0KC+rZB\n" +
                "oO3tu9PR7H75K5G2eT6oUWkWKcZZU/4WNCDasNtizTe41Jy99BjrChww5r2ctqG8\n" +
                "LvIv7UeeFaK1vhxGKaNH/7JvKJI9LbewWNtmb/nRzQg9xK3e0OhblbW+o6zg5pTw\n" +
                "+n37fS7pkXK7lbRfUfaQmhoGy6ox4UWGmOgm8yPu8S4Q==</Modulus><Exponen\n" +
                "t>AQAB</Exponent></RSAKeyValue>";

        HashMap<String, BigInteger> pubKeyAsMap = RsaHelper.XmlKeyParser.parseKeyFromXmlString(examplePubKey);
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

        HashMap<String, BigInteger> pubKeyAsMap = RsaHelper.XmlKeyParser.parseKeyFromXmlString(examplePrivateKey);
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
        PublicKey pubKey = RsaHelper.createPublicKey(pubKeyAsMap);
        assertEquals("X.509", pubKey.getFormat());

        logger.info(pubKey.toString());
        logger.info("-----BEGIN PUBLIC KEY-----");
        logger.info(Base64.getEncoder().encodeToString(pubKey.getEncoded()));
        logger.info("-----END PUBLIC KEY-----");

        Cipher cipher = Cipher.getInstance(RsaHelper.RSA_OAEP);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] cipherData = cipher.doFinal(TEST_STRING.getBytes(StandardCharsets.UTF_8));
        String encrypted = Base64.getEncoder().encodeToString(cipherData);
        logger.info("Encrypted message: " + encrypted);
    }

    private HashMap<String, BigInteger> createTestPubKeyAsMap() {
        var pubKeyAsMap = new HashMap<String, BigInteger>();
        var mod = RsaHelper.XmlKeyParser.parseEncodedBigInteger("xs1GwyPre7/knVd3CAO1pyk++yp/qmBz2TekgrehYT\n" +
                "WU7hs8bUCeVQrL2OB+jm/AgjdPMohWHD/tLcJy35aZgVfPI3Oa3gmXxdoLZrfNRb\n" +
                "nrCm3Xr1MR7wnhMyBt5XXyU/FiF46g5qJ2DUIUg7teoKDNUSAN81JTIoH0KC+rZB\n" +
                "oO3tu9PR7H75K5G2eT6oUWkWKcZZU/4WNCDasNtizTe41Jy99BjrChww5r2ctqG8\n" +
                "LvIv7UeeFaK1vhxGKaNH/7JvKJI9LbewWNtmb/nRzQg9xK3e0OhblbW+o6zg5pTw\n" +
                "+n37fS7pkXK7lbRfUfaQmhoGy6ox4UWGmOgm8yPu8S4Q==");
        var exp = RsaHelper.XmlKeyParser.parseEncodedBigInteger("AQAB");

        pubKeyAsMap.put("Modulus", mod);
        pubKeyAsMap.put("Exponent", exp);
        return pubKeyAsMap;
    }

}