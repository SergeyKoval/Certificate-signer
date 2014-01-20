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
    public static final Date END_DATE = new GregorianCalendar(2024, Calendar.JANUARY, 13).getTime();

    public static final String ROOT_CERT_PATH = "D:/mdp_root.cer";
    public static final String ROOT_PRIV_PATH = "D:/mdp_root.pem";

    public static final String SIGNED_CERT_PATH = "D:/mdp_default.cer";
    public static final String SIGNED_PRIV_PATH = "D:/mdp_default.pem";

    public static final String ROOT_CN = "mdp";
    public static final String SIGNED_CN = "mdp default";

    public static final String ROOT_PFX_PATH = "D:/root.pfx";
    public static final String ROOT_PFX_PASS = "LsmbHqnO5pQlKsmo9VHK";
    public static final String CERT_PFX_PATH = "D:/mdp_default.pfx";
    public static final String CERT_PFX_PASS = "vregfetrgsgdfew";

    public static final String STORE_PATH = "D:/serverstore";
    public static final String STORE_TYPE = "JKS";
    public static final String STORE_PASS = "GFLCEzZpaymV5sgfEdSc";
    public static final String TRUSTED_STORE_PATH = "D:/trustedstore";
    public static final String TRUSTED_STORE_TYPE = "JKS";
    public static final String TRUSTED_STORE_PASS = "u0QV1FTxNR4AoB4ayBXu";


    public static void main(String[] args) throws Exception {
        X509Certificate rootCert;
        PrivateKey rootPrivateKey;
        CertificateUtils certBuilder = CertificateUtils.getInstance(new BouncyCastleProvider(), SIGNING_ALG);

        // Generate keys for self-signed certificate (rootCert)
        // and certificate signed by root
        KeyGenUtils keyGenUtils = KeyGenUtils.getInstance(KEY_SIZE, KEY_GEN_ALG, BouncyCastleProvider.PROVIDER_NAME);
        KeyPair rootKeys = keyGenUtils.generateKeys();
        KeyPair testKeys = keyGenUtils.generateKeys();
        // --------------------------------------------------------

        // Create root certificate
//        rootCert = generateRootCert(certBuilder, rootKeys);
//        rootPrivateKey = rootKeys.getPrivate();
        // Get certificate + private from keystore
        rootCert = loadRootCertFromKeyStore();
        rootPrivateKey = loadPrivateKeyFromKeyStore();
        // --------------------------------------------------------

        // Save root certificate to stores
//        addRootCertToServerStoreAndSaveStore(rootCert, rootKeys.getPrivate());
//        addRootCertToTrustedStoreAndSaveStore(rootCert);
        // --------------------------------------------------------

        // Create signed certificate
        X509Certificate testCert = certBuilder.newCertificate(rootCert, rootPrivateKey, new X500Name("CN=" + SIGNED_CN), testKeys, START_DATE, END_DATE);
        // --------------------------------------------------------

        // Save certificates as PEM to generate pfx by OPENSSL
        saveRootCertToDisk(rootCert, rootPrivateKey);
        saveCertToDisk(testCert, testKeys.getPrivate());
        // --------------------------------------------------------

        //Save certificates to pfx files
        PfxUtils.saveAsPfx(ROOT_PRIV_PATH, ROOT_CERT_PATH, ROOT_PFX_PATH, ROOT_PFX_PASS);
        PfxUtils.saveAsPfx(SIGNED_PRIV_PATH, SIGNED_CERT_PATH, CERT_PFX_PATH, CERT_PFX_PASS);
    }

    private static void addRootCertToServerStoreAndSaveStore(X509Certificate rootCert, PrivateKey pkey) throws Exception {
        KeyStore keyStore = KeyStoreUtils.getKeyStore(STORE_PATH, STORE_TYPE, STORE_PASS);
        keyStore.setKeyEntry(ROOT_CN, pkey, STORE_PASS.toCharArray(), new Certificate[] {rootCert});
        KeyStoreUtils.saveKeyStore(STORE_PATH, keyStore, STORE_PASS);
    }

    private static void addRootCertToTrustedStoreAndSaveStore(X509Certificate rootCert) throws Exception {
        KeyStore trustedStore = KeyStoreUtils.getKeyStore(TRUSTED_STORE_PATH, TRUSTED_STORE_TYPE, TRUSTED_STORE_PASS);
        trustedStore.setCertificateEntry(ROOT_CN, rootCert);
        KeyStoreUtils.saveKeyStore(TRUSTED_STORE_PATH, trustedStore, TRUSTED_STORE_PASS);
    }

    private static void saveRootCertToDisk(X509Certificate rootCert, PrivateKey pkey) throws Exception {
        PemUtils.saveAsFile(rootCert, ROOT_CERT_PATH);
        PemUtils.saveAsFile(pkey, ROOT_PRIV_PATH);
    }

    private static void saveCertToDisk(X509Certificate cert, PrivateKey pkey) throws Exception {
        PemUtils.saveAsFile(cert, SIGNED_CERT_PATH);
        PemUtils.saveAsFile(pkey, SIGNED_PRIV_PATH);
    }

    private static X509Certificate generateRootCert(CertificateUtils certBuilder, KeyPair rootKeys) throws Exception {
        return certBuilder.newSelfSignedCertificate(new X500Name("CN=" + ROOT_CN), rootKeys, START_DATE, END_DATE);
    }

    private static X509Certificate loadRootCertFromKeyStore() throws Exception {
        KeyStore keyStore = KeyStoreUtils.getKeyStore(STORE_PATH, STORE_TYPE, STORE_PASS);
        return (X509Certificate) keyStore.getCertificate(ROOT_CN);
    }

    private static PrivateKey loadPrivateKeyFromKeyStore() throws Exception {
        KeyStore keyStore = KeyStoreUtils.getKeyStore(STORE_PATH, STORE_TYPE, STORE_PASS);
        return (PrivateKey) keyStore.getKey(ROOT_CN, STORE_PASS.toCharArray());
    }
}