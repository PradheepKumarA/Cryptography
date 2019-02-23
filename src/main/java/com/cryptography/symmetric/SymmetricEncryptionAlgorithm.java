package com.cryptography.symmetric;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

/**
 * SymmetricEncryptionAlgorithm
 *
 * @author PradheepKumarA
 * @date 2019-02-23
 */
public class SymmetricEncryptionAlgorithm {

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        Scanner in = new Scanner(System.in);
        System.out.println("Enter the String to be encoded : ");
        String data = in.nextLine();
        System.out.println("Enter the secret value : ");
        String secret = in.nextLine();
        System.out.println("Enter the Algorithm - AES : ");
        String algorithm = in.nextLine();

        String encryptedData = encryptString(data, secret, algorithm);
        System.out.println("Encrypted data : " + encryptedData);

        String decryptedData = decryptString(encryptedData, secret, algorithm);
        System.out.println("Decrypted data : " + decryptedData);
    }

    public static String encryptString(String data, String secret, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Key secretKey = new SecretKeySpec(Arrays.copyOf(secret.getBytes("UTF-8"), 16), algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(data.getBytes());
        return new BASE64Encoder().encode(encryptedByte);
    }

    public static String decryptString(String encryptedData, String secret, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Key secretKey = new SecretKeySpec(Arrays.copyOf(secret.getBytes("UTF-8"), 16), algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] originalData = cipher.doFinal(decodedBytes);
        return new String(originalData);
    }
}