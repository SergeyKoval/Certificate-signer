package com.exadel.certificates;

import com.exadel.certificates.util.CertificateUtils;
import com.exadel.certificates.util.KeyStoreUtils;
import com.exadel.certificates.util.KeyUtils;
import com.exadel.certificates.util.PemUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class Main {

    private static final int KEY_SIZE = 2048;
    private static final String KEY_GEN_ALG = "RSA";
    private static final String SIGNING_ALG = "SHA256WithRSAEncryption";


    public static void main(String[] args) throws OperatorCreationException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, IOException, KeyStoreException {

        CertificateUtils certBuilder = CertificateUtils.getInstance(new BouncyCastleProvider());
        certBuilder.setSigningAlg(SIGNING_ALG);

        // Create date interval for new certificates
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2015);

        Date notAfter = calendar.getTime();
        Date notBefore = new Date(System.currentTimeMillis());
        // --------------------------------------------------------

        // Generate keys for self-signed certificate (rootCert)
        // and certificate signed by rootCert (testCert)
        KeyUtils keyUtils = KeyUtils.getInstance(KEY_SIZE, KEY_GEN_ALG, BouncyCastleProvider.PROVIDER_NAME);
        KeyPair rootKeys = keyUtils.generateKeys();
        KeyPair testKeys = keyUtils.generateKeys();
        // --------------------------------------------------------

        // Create rootCert
        X509Certificate rootCert
                = certBuilder.newSelfSignedCertificate(new X500Name("CN=root"), rootKeys, notBefore, notAfter);
        // --------------------------------------------------------

        // Save rootCert to keyStore
        KeyStore keyStore = KeyStoreUtils.getKeyStore("D://teststore", "JKS", "test");
        keyStore.setKeyEntry("rootCA", rootKeys.getPrivate(),
                "test".toCharArray(), new Certificate[]{rootCert});
        // --------------------------------------------------------

        // Create testCert
        X509Certificate testCert
                = certBuilder.newCertificate(rootCert, rootKeys.getPrivate(), new X500Name("CN=testCert"), testKeys,
                notBefore, notAfter);
        // --------------------------------------------------------

        // Save testCert to keyStore
        keyStore.setKeyEntry("testCert", testKeys.getPrivate(),
                "test".toCharArray(), new Certificate[]{testCert, rootCert});
        KeyStoreUtils.saveKeyStore("D://teststore", keyStore, "test");
        // --------------------------------------------------------

        // Save certificates as PEM to generate pfx by OPENSSL
        PemUtils.saveAsFile(rootCert, "D://root_cert.cert");
        PemUtils.saveAsFile(rootKeys.getPrivate(), "D://root_priv.pem");

        PemUtils.saveAsFile(testCert, "D://test_cert.cert");
        PemUtils.saveAsFile(testKeys.getPrivate(), "D://test_priv.pem");
        // --------------------------------------------------------

        // Certificate validation
        // name.checkValidity(new Date());
        // name.verify(resultCertificate.getPublicKey());
    }
}