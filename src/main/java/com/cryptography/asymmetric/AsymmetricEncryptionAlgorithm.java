package com.cryptography.asymmetric;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * AsymmetricEncryptionAlgorithm
 *
 * @author PradheepKumarA
 * @date 2019-02-23
 */
public class AsymmetricEncryptionAlgorithm {

    private String privateKey;
    private String publicKey;
    private String algorithm = "RSA";

    public AsymmetricEncryptionAlgorithm() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = new BASE64Encoder().encode(keyPair.getPublic().getEncoded());
        privateKey = new BASE64Encoder().encode(keyPair.getPrivate().getEncoded());
        System.out.println("public : " + publicKey);
        System.out.println("private : " + privateKey);
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, NoSuchPaddingException, IOException {
        AsymmetricEncryptionAlgorithm encryptionAlgorithm = new AsymmetricEncryptionAlgorithm();
        String originalData = "data1";
        System.out.println("Original Data : " + originalData);

        String encryptedData = encryptionAlgorithm.encryptString(originalData);
        System.out.println("Encrypted Data : " + encryptedData);
        String decryptedData = encryptionAlgorithm.decryptString(encryptedData);
        System.out.println("Decrypted Data : " + decryptedData);
    }


    public String encryptString(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        cipher.doFinal(data.getBytes());
        byte[] encryptedByte = cipher.doFinal(data.getBytes());
        return new BASE64Encoder().encode(encryptedByte);
    }

    private PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    public String decryptString(String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        byte[] decryptedBytes = cipher.doFinal(new BASE64Decoder().decodeBuffer(encryptedData));
        return new String(decryptedBytes);
    }

    private PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }
}
