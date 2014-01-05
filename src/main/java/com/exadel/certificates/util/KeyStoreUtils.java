package com.exadel.certificates.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class KeyStoreUtils {

    private static KeyStoreUtils instance;


    private KeyStoreUtils() {

    }

    public static KeyStore getKeyStore(String path, String type, String password)
            throws NoSuchProviderException, KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {

        File keyStore = new File(path);
        KeyStore store = KeyStore.getInstance(type);

        if (keyStore.exists()) {
            FileInputStream fistream = new FileInputStream(keyStore);
            store.load(fistream, password.toCharArray());
            fistream.close();
        } else {
            store.load(null);
        }

        return store;
    }


    public static void saveKeyStore(String path, KeyStore keyStore, String password)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {

        FileOutputStream fostream = new FileOutputStream(new File(path));
        keyStore.store(fostream, password.toCharArray());
        fostream.close();
    }


    public static KeyStoreUtils getInstance() {

        if (instance == null) {
            instance = new KeyStoreUtils();
        }

        return instance;
    }
}
