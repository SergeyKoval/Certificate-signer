package com.exadel.certificates;

import com.exadel.certificates.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class Main {

    public static final int KEY_SIZE = 2048;
    public static final String KEY_GEN_ALG = "RSA";
    public static final String SIGNING_ALG = "SHA256WithRSAEncryption";

    public static final Date START_DATE = new GregorianCalendar(2014, Calendar.JANUARY, 13).getTime();
    public static final Date END_DATE = new GregorianCalendar(2015, Calendar.JANUARY, 13).getTime();

    public static final String ROOT_CERT_PATH = "D:/root_cert.cer";
    public static final String ROOT_PRIV_PATH = "D:/root_priv.pem";

    public static final String SIGNED_CERT_PATH = "D:/test_cert.cer";
    public static final String SIGNED_PRIV_PATH = "D:/test_priv.pem";

    public static final String ROOT_CN = "root";
    public static final String SIGNED_CN = "signed";

    public static final String PFX_PATH = "D:/test.pfx";
    public static final String PFX_PASS = "pfxpass";

    public static final String STORE_PATH = "D:/teststore";
    public static final String STORE_TYPE = "JKS";
    public static final String STORE_PASS = "storepass";


    public static void main(String[] args) throws Exception {

        CertificateUtils certBuilder = CertificateUtils.getInstance(new BouncyCastleProvider());
        certBuilder.setSigningAlg(SIGNING_ALG); // It isn't necessary. SHA256WithRSAEncryption used by default

        // Generate keys for self-signed certificate (rootCert)
        // and certificate signed by root
        KeyGenUtils keyGenUtils = KeyGenUtils.getInstance(KEY_SIZE, KEY_GEN_ALG, BouncyCastleProvider.PROVIDER_NAME);
        KeyPair rootKeys = keyGenUtils.generateKeys();
        KeyPair testKeys = keyGenUtils.generateKeys();
        // --------------------------------------------------------

        // Create root certificate
        X509Certificate rootCert
                = certBuilder.newSelfSignedCertificate(new X500Name("CN=" + ROOT_CN), rootKeys, START_DATE, END_DATE);
        // --------------------------------------------------------

        // Save root certificate to keyStore
        KeyStore keyStore = KeyStoreUtils.getKeyStore(STORE_PATH, STORE_TYPE, STORE_PASS);
        keyStore.setKeyEntry(ROOT_CN, rootKeys.getPrivate(),
                STORE_PASS.toCharArray(), new Certificate[] {rootCert});

        KeyStoreUtils.saveKeyStore(STORE_PATH, keyStore, STORE_PASS);
        // --------------------------------------------------------

        // Create signed certificate
        X509Certificate testCert
                = certBuilder.newCertificate(rootCert, rootKeys.getPrivate(), new X500Name("CN=" + SIGNED_CN), testKeys,
                START_DATE, END_DATE);
        // --------------------------------------------------------

        // Save certificates as PEM to generate pfx by OPENSSL
        PemUtils.saveAsFile(rootCert, ROOT_CERT_PATH);
        PemUtils.saveAsFile(rootKeys.getPrivate(), ROOT_PRIV_PATH);

        PemUtils.saveAsFile(testCert, SIGNED_CERT_PATH);
        PemUtils.saveAsFile(testKeys.getPrivate(), SIGNED_PRIV_PATH);
        // --------------------------------------------------------

        PfxUtils.saveAsPfx(ROOT_PRIV_PATH, ROOT_CERT_PATH, PFX_PATH, PFX_PASS);


        /* // Get certificate + private from keystore
        keyStore = KeyStoreUtils.getKeyStore(STORE_PATH, STORE_TYPE, STORE_PASS);
        X509Certificate cert = keyStore.getCertificate("alias");
        PrivateKey pkey = keyStore.getKey("alias", STORE_PASS);
        */

        // Certificate validation
        // name.checkValidity(new Date());
        // name.verify(resultCertificate.getPublicKey());
    }
}