package com.exadel.certificates.util;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PfxUtils {

    private PfxUtils() {

    }


    public static void saveAsPfx(String keyFilePath, String cerFilePath,
                                 String pfxPath, final String password)
            throws IOException, NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException {

        FileReader reader = new FileReader(keyFilePath);
        PEMReader pem = new PEMReader(reader, new PasswordFinder() {
            @Override
            public char[] getPassword() {
                return password.toCharArray();
            }
        });

        PrivateKey privateKey = ((KeyPair) pem.readObject()).getPrivate();

        pem.close();
        reader.close();

        reader = new FileReader(cerFilePath);
        pem = new PEMReader(reader);

        X509Certificate cert = (X509Certificate) pem.readObject();

        pem.close();
        reader.close();

        saveAsPfx(privateKey, cert, pfxPath, password);
    }


    public static void saveAsPfx(PrivateKey privateKey, X509Certificate cert,
                                 String pfxPath, String password)
            throws IOException, NoSuchProviderException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException {

        FileOutputStream fos = new FileOutputStream(new File("D:/testpfx.pfx"));
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null);
        store.setKeyEntry("alias", privateKey, password.toCharArray(), new java.security.cert.Certificate[]{cert});
        store.store(fos, password.toCharArray());

        fos.close();
    }
}
