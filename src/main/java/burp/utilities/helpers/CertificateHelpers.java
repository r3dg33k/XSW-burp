package burp.utilities.helpers;

import burp.utilities.exceptions.SAMLException;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class CertificateHelpers {
    public X509Certificate clone(String certificate) throws SAMLException {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate originalCertificate =
                    (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certificate)));
            PublicKey originalPublicKey = originalCertificate.getPublicKey();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(originalPublicKey.getAlgorithm());
            kpg.initialize(((RSAPublicKey) originalCertificate.getPublicKey()).getModulus().bitLength());
            KeyPair fakedKeyPair = kpg.generateKeyPair();

            X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

            v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            v3CertGen.setIssuerDN(originalCertificate.getIssuerX500Principal());
            v3CertGen.setNotAfter(originalCertificate.getNotAfter());
            v3CertGen.setNotBefore(originalCertificate.getNotBefore());
            v3CertGen.setSubjectDN(originalCertificate.getSubjectX500Principal());
            v3CertGen.setSignatureAlgorithm(originalCertificate.getSigAlgName());
            v3CertGen.setPublicKey(fakedKeyPair.getPublic());

            return v3CertGen.generate(fakedKeyPair.getPrivate());
        } catch (CertificateException | NoSuchAlgorithmException | SignatureException | InvalidKeyException |
                 IllegalArgumentException | NullPointerException e) {
            throw new SAMLException(e);
        }
    }
}
