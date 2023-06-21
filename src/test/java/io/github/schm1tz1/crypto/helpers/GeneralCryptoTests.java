package io.github.schm1tz1.crypto.helpers;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class GeneralCryptoTests {

    @Test
    void listAvailableAlgorithms() {
        List<String> algorithms = Arrays.stream(Security.getProviders())
                .flatMap(provider -> provider.getServices().stream())
                .filter(service -> "Cipher".equals(service.getType()))
                .map(Provider.Service::getAlgorithm)
                .collect(Collectors.toList());
        System.out.println(algorithms.stream().sorted().collect(Collectors.toList()));
        assert algorithms.contains("RSA");
        assert algorithms.contains("AES");
    }

    @Test
    void checkForAlgorithms() throws NoSuchPaddingException, NoSuchAlgorithmException {
        String[] algorithms = {
                AesProvider.AES_GCM, AesProvider.AES_CBC, AesProvider.AES_ECB,
                RsaProvider.RSA_OAEP, RsaProvider.RSA_OAEP_SHA256_MGF1,
                "RSA/ECB/OAEPWithMD5AndMGF1Padding"
        };

        Arrays.stream(algorithms).forEach(algorithm -> {
            try {
                Cipher.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            }
        });
    }

}
