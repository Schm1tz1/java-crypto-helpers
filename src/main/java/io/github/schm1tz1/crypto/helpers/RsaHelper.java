package io.github.schm1tz1.crypto.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

/**
 * Helper Class for RSA-based Asymmetric Cryptography
 */
public class RsaHelper {

    public static final String RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
    public static final String RSA_OAEP = "RSA/ECB/OAEPPadding";
    public static final String RSA_OAEP_SHA256_MGF1 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final Logger log = LoggerFactory.getLogger(RsaHelper.class);

    public RsaHelper() {
    }

    static PublicKey createPublicKey(HashMap<String, BigInteger> keySpecs) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(keySpecs.get("Modulus"), keySpecs.get("Exponent"))
        );
        return pubKey;
    }

    static PrivateKey createPrivateKey(HashMap<String, BigInteger> keySpecs) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(keySpecs.get("Modulus")
                        , keySpecs.get("Exponent")
                        , keySpecs.get("D"), keySpecs.get("P"), keySpecs.get("Q")
                        , keySpecs.get("DP"), keySpecs.get("DQ"), keySpecs.get("InverseQ"))
        );

        return privateKey;
    }

    class XmlKeyParser {

        static BigInteger parseEncodedBigInteger(String inputString) {
            if (inputString != null) {
                String filteredString = filterSpecialCharacters(inputString);
                return new BigInteger(1, Base64.getDecoder().decode(filteredString));
            }
            return null;
        }

        static HashMap<String, BigInteger> parseKeyFromXmlString(String xmlInput) {
            DocumentBuilder db = null;
            String filteredXmlInput = filterSpecialCharacters(xmlInput);

            try {
                db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            } catch (ParserConfigurationException e) {
                throw new RuntimeException("Error setting up XML parser: ", e);
            }
            Element elementsByTagName = null;
            try {
                elementsByTagName = db.parse(new ByteArrayInputStream(filteredXmlInput.getBytes())).getDocumentElement();
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
                if (firstItem == null) {
                    return;
                }
                var numberValue = parseEncodedBigInteger(firstItem.getTextContent());
                if (numberValue != null) {
                    values.put(key, numberValue);
                }
            });
            return values;
        }

        private static String filterSpecialCharacters(String xmlInput) {
            if (xmlInput != null) {
                var filteredXmlInput = xmlInput
                        .replaceAll("[\\t\\r\\n]+", "");
                return filteredXmlInput;
            }
            return null;
        }
    }

}
