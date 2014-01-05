package com.exadel.certificates.util;


import java.security.*;

public class KeyUtils {

    private KeyPairGenerator keysGen;

    private static KeyUtils instance;


    private KeyUtils(int keySize, String algorithm, String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        keysGen = KeyPairGenerator.getInstance(algorithm, providerName);
        keysGen.initialize(keySize, new SecureRandom());
    }


    public KeyPair generateKeys() {
        return keysGen.generateKeyPair();
    }


    public static KeyUtils getInstance(int keySize, String algorithm, String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        if (instance == null) {
            instance = new KeyUtils(keySize, algorithm, providerName);
        }

        return instance;
    }
}
