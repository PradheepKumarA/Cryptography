package com.cryptography.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SymmetricEncryptionAlgorithmTest
 *
 * @author PradheepKumarA
 * @date 2019-02-23
 */
class SymmetricEncryptionAlgorithmTest {

    @Test
    void encryptString() throws NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String originalData = "data";
        String secret = "secret0123456789";
        String algorithm = "AES";
        String expectedEntryptedData = "RzozDO/vI1sqTG9sOHIiew==";

        String actualEncryptedData = SymmetricEncryptionAlgorithm.encryptString(originalData, secret, algorithm);
        assertEquals(expectedEntryptedData, actualEncryptedData, "should encrypt in AES");
    }

    @Test
    void decryptString() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        String originalData = "data";
        String secret = "secret0123456789";
        String algorithm = "AES";

        String encryptedData = SymmetricEncryptionAlgorithm.encryptString(originalData, secret, algorithm);
        String decryptedData = SymmetricEncryptionAlgorithm.decryptString(encryptedData, secret, algorithm);
        assertEquals(originalData, decryptedData, "should decrypt in AES");
    }
}