package com.exadel.certificates.util;


import java.security.*;

public class KeyGenUtils {

    private KeyPairGenerator keysGen;

    private static KeyGenUtils instance;


    private KeyGenUtils(int keySize, String algorithm, String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        keysGen = KeyPairGenerator.getInstance(algorithm, providerName);
        keysGen.initialize(keySize, new SecureRandom());
    }


    public KeyPair generateKeys() {
        return keysGen.generateKeyPair();
    }


    public static KeyGenUtils getInstance(int keySize, String algorithm, String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        if (instance == null) {
            instance = new KeyGenUtils(keySize, algorithm, providerName);
        }

        return instance;
    }
}
