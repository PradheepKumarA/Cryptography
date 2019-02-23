package com.cryptography.messagedigest;

import java.security.MessageDigest;
import java.util.Scanner;

/**
 * DigestEncryptionAlgorithm.java - a simple class for MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 encryption
 *
 * @author - PradheepKumarA
 * @date - 2019-02-18
 */
public class DigestEncryptionAlgorithm {
    public static void main(String[] a) {
        Scanner in = new Scanner(System.in);
        // Get the stringToBeEncoded from console
        System.out.print("Enter the String to be encrypted : ");
        String stringToBeEncoded = in.nextLine();
        System.out.print("Enter the Algorithm - MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 : ");
        String encodingAlgorithm = in.nextLine();
        String shaEncodedString = encryptString(stringToBeEncoded, encodingAlgorithm);

        // Print the Encrypted String
        System.out.println("Encrypted value : " + shaEncodedString);
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

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
