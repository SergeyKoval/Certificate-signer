package com.exadel.certificates.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PfxUtils {
    private static final String PKCS_12 = "PKCS12";
    private static final String BC = "BC";
    private static final String ALIAS = "alias";

    private PfxUtils() {

    }

    public static void saveAsPfx(String keyFilePath, String cerFilePath, String pfxPath, final String password)
            throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException {

        PrivateKey privateKey = CertificateUtils.getPrivateFromPem(keyFilePath);
        X509Certificate cert = CertificateUtils.getCertifivateFromPem(cerFilePath);

        saveAsPfx(privateKey, cert, pfxPath, password);
    }

    public static void saveAsPfx(PrivateKey privateKey, X509Certificate cert, String pfxPath, String password)
            throws IOException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        FileOutputStream fos = new FileOutputStream(new File(pfxPath));
        KeyStore store = KeyStore.getInstance(PKCS_12, BC);

        store.load(null);
        store.setKeyEntry(ALIAS, privateKey, password.toCharArray(), new java.security.cert.Certificate[]{cert});
        store.store(fos, password.toCharArray());

        fos.close();
    }
}