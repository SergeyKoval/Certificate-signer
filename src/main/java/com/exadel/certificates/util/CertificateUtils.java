package com.exadel.certificates.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateUtils {

    private String signingAlg = "SHA256WithRSAEncryption";
    private String providerName;

    private static CertificateUtils instance;


    private CertificateUtils(Provider provider) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException, OperatorCreationException {
        Security.addProvider(provider);
        providerName = provider.getName();
    }


    public String getSigningAlg() {
        return signingAlg;
    }


    public void setSigningAlg(String signingAlg) {
        this.signingAlg = signingAlg;
    }


    public String getProviderName() {
        return providerName;
    }


    public static PrivateKey getPrivateFromPem(String keyPemPath) throws IOException {
        FileReader reader = new FileReader(keyPemPath);
        PEMReader pem = new PEMReader(reader);
        PrivateKey key = ((KeyPair) pem.readObject()).getPrivate();

        pem.close();
        reader.close();

        return key;
    }


    public static X509Certificate getCertifivateFromPem(String cerFilePath) throws IOException {
        FileReader reader = new FileReader(cerFilePath);
        PEMReader pem = new PEMReader(reader);

        X509Certificate cert = (X509Certificate) pem.readObject();

        pem.close();
        reader.close();

        return cert;
    }


    public X509Certificate newCertificate(X509Certificate issuer, PrivateKey issuerPK, X500Name subject,
                                          KeyPair keys, Date notBefore, Date notAfter)
            throws NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException,
            CertificateException, IOException {

        BigInteger serial = generateSerial();
        X500Principal subjPrincipal = new X500Principal(subject.toString());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                serial, notBefore, notAfter, subjPrincipal, keys.getPublic());

        return buildSignedCertificate(issuerPK, certBuilder);
    }


    public X509Certificate newSelfSignedCertificate(X500Name subject, KeyPair keys,
                                                    Date notBefore, Date notAfter)
            throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
            OperatorCreationException, IOException {

        BigInteger serial = generateSerial();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject,
                serial, notBefore, notAfter, subject, keys.getPublic());

        return buildSignedCertificate(keys.getPrivate(), certBuilder);
    }


    private BigInteger generateSerial() {
        return BigInteger.valueOf(System.currentTimeMillis());
    }


    private X509Certificate buildSignedCertificate(PrivateKey issuerPK, X509v3CertificateBuilder certBuilder)
            throws OperatorCreationException, CertificateException {

        ContentSigner signer = buildSigner(signingAlg, providerName, issuerPK);
        JcaX509CertificateConverter converter = getCertificateConverter(providerName);

        return converter.getCertificate(certBuilder.build(signer));
    }


    private ContentSigner buildSigner(String signatureAlgorithm,
                                      String providerName, PrivateKey privateKey)
            throws OperatorCreationException {

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        signerBuilder = signerBuilder.setProvider(providerName); // TODO don't know, need i to reinit signerBuilder or not

        return signerBuilder.build(privateKey);
    }


    private JcaX509CertificateConverter getCertificateConverter(String provider) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter = converter.setProvider(provider); // TODO don't know, need i to reinit signerBuilder or not

        return converter;
    }


    public static CertificateUtils getInstance(Provider provider) throws OperatorCreationException,
            CertificateException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        if (instance == null) {
            instance = new CertificateUtils(provider);
        }

        return instance;
    }
}

// TODO Make the function "extendCertificatePeriod"
