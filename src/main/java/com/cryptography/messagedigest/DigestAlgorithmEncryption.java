package com.cryptography.messagedigest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.security.MessageDigest;

/**
 * DigestAlgorithmEncryption.java - a simple class for MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 encryption
 *
 * @author - PradheepKumarA
 * @date - 18 Feb 2019
 */

public class DigestAlgorithmEncryption {
    public static void main(String[] a) {
        Scanner in = new Scanner(System.in);
        // Get the stringToBeEncoded from console
        String stringToBeEncoded = in.nextLine();
        String encodingAlgorithm = in.nextLine();
        String shaEncodedString = encryptString(stringToBeEncoded, encodingAlgorithm);

        // Print the Encrypted String
        System.out.println(shaEncodedString);
    }

    public static String encryptString(String input, String algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] digest = messageDigest.digest(input.getBytes("UTF-8"));
            return bytesToHex(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
