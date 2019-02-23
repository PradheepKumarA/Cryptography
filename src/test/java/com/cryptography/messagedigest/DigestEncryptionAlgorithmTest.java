package com.cryptography.messagedigest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DigestEncryptionAlgorithm.java - a simple class for MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 encryption
 *
 * @author - PradheepKumarA
 * @date - 2019-02-19
 */

class DigestEncryptionAlgorithmTest {

    public String originalString = "original";

    @Test
    void testMD2Encription() {
        String expected = "7d6f9b1abcf7f123fab941f08eb0b8e9";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "MD2");
        assertEquals(expected, actual, "should encrypt in MD2");
    }

    @Test
    void testMD5Encription() {
        String expected = "919c8b643b7133116b02fc0d9bb7df3f";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "MD5");
        assertEquals(expected, actual, "should encrypt in MD2");
    }

    @Test
    void testSHA1Encription() {
        String expected = "d73ef92426f2b11dfc4aed4d4bfc41c49ee1087c";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "SHA-1");
        assertEquals(expected, actual, "should encrypt in SHA-1");
    }

    @Test
    void testSHA244Encription() {
        String expected = "3f90eb8c61672169a2889615823bd77849e471867d7902cc0fc5eb8a";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "SHA-224");
        assertEquals(expected, actual, "should encrypt in SHA-224");
    }

    @Test
    void testSHA256Encription() {
        String expected = "0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "SHA-256");
        assertEquals(expected, actual, "should encrypt in SHA-256");
    }

    @Test
    void testSHA384Encription() {
        String expected = "4fec25d1fefd10a337ca52e0e1485343e0cf20450b8a44a4ffd7a53aaab43f7f5cc4ac0eed44f0e69d7941ea78935559";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "SHA-384");
        assertEquals(expected, actual, "should encrypt in SHA-384");
    }

    @Test
    void testSHA512Encription() {
        String expected = "c5ee067fb433795d5c8efeca78623791dc6ce524198b7223fe8310f81a38c9105da8a61714dd5a633e52dac7b57b33948afd94cb37c522f89781c9c25471a9c3";
        String actual = DigestEncryptionAlgorithm.encryptString(originalString, "SHA-512");
        assertEquals(expected, actual, "should encrypt in SHA-512");
    }
}
