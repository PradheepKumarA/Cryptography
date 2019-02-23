package com.cryptography.asymmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * AsymmetricEncryptionAlgorithmTest
 *
 * @author PradheepKumarA
 * @date 2019-02-24
 */
class AsymmetricEncryptionAlgorithmTest {

    @Test
    void testRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        AsymmetricEncryptionAlgorithm encryptionAlgorithm = new AsymmetricEncryptionAlgorithm();
        String originalData = "data";

        String encryptedData = encryptionAlgorithm.encryptString(originalData);
        String decryptedData = encryptionAlgorithm.decryptString(encryptedData);
        assertEquals(originalData, decryptedData, "Should encrypt and decrypt with RSA");
    }
}
