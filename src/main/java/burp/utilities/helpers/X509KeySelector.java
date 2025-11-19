package burp.utilities.helpers;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * X509KeySelector for XML Signature validation.
 * Supports all common signature algorithms for RSA, DSA, and ECDSA.
 */
public class X509KeySelector extends KeySelector {

    @Override
    public KeySelectorResult select(KeyInfo keyInfo,
                                    Purpose purpose,
                                    AlgorithmMethod method,
                                    XMLCryptoContext context)
            throws KeySelectorException {

        if (keyInfo == null) {
            throw new KeySelectorException("KeyInfo is null");
        }

        String signatureAlgorithm = method.getAlgorithm();
        List<X509Certificate> certificates = extractCertificates(keyInfo);

        if (certificates.isEmpty()) {
            throw new KeySelectorException("No X509 certificates found in KeyInfo");
        }

        // Try to find a certificate with a compatible public key
        for (X509Certificate cert : certificates) {
            PublicKey publicKey = cert.getPublicKey();
            if (isAlgorithmCompatible(signatureAlgorithm, publicKey.getAlgorithm())) {
                return new SimpleKeySelector(publicKey);
            }
        }

        // If no compatible key found, provide detailed error
        String availableAlgorithms = getAvailableAlgorithms(certificates);
        throw new KeySelectorException(
                String.format("No compatible key found for signature algorithm '%s'. Available key algorithms: %s",
                        signatureAlgorithm, availableAlgorithms)
        );
    }

    /**
     * Extract all X509 certificates from KeyInfo
     */
    private List<X509Certificate> extractCertificates(KeyInfo keyInfo) {
        List<X509Certificate> certificates = new ArrayList<>();

        @SuppressWarnings("unchecked")
        Iterator<XMLStructure> iter = keyInfo.getContent().iterator();

        while (iter.hasNext()) {
            XMLStructure structure = iter.next();
            if (structure instanceof X509Data x509Data) {
                extractCertificatesFromX509Data(x509Data, certificates);
            }
        }

        return certificates;
    }

    /**
     * Extract certificates from X509Data element
     */
    private void extractCertificatesFromX509Data(X509Data x509Data, List<X509Certificate> certificates) {
        @SuppressWarnings("rawtypes")
        Iterator iter = x509Data.getContent().iterator();

        while (iter.hasNext()) {
            Object obj = iter.next();
            if (obj instanceof X509Certificate) {
                certificates.add((X509Certificate) obj);
            }
        }
    }

    /**
     * Get available algorithms from certificates for error reporting
     */
    private String getAvailableAlgorithms(List<X509Certificate> certificates) {
        List<String> algorithms = new ArrayList<>();
        for (X509Certificate cert : certificates) {
            String alg = cert.getPublicKey().getAlgorithm();
            if (!algorithms.contains(alg)) {
                algorithms.add(alg);
            }
        }
        return String.join(", ", algorithms);
    }

    /**
     * Check if signature algorithm is compatible with key algorithm
     */
    private boolean isAlgorithmCompatible(String signatureAlgorithm, String keyAlgorithm) {
        // Normalize key algorithm name
        keyAlgorithm = keyAlgorithm.toUpperCase();

        // RSA algorithms
        if ("RSA".equals(keyAlgorithm)) {
            return signatureAlgorithm.equals(SignatureMethod.RSA_SHA1) ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") ||
                    signatureAlgorithm.equals("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        }

        // DSA algorithms
        if ("DSA".equals(keyAlgorithm)) {
            return signatureAlgorithm.equals(SignatureMethod.DSA_SHA1) ||
                    signatureAlgorithm.equals("http://www.w3.org/2009/xmldsig11#dsa-sha256") ||
                    signatureAlgorithm.equals("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
        }

        // ECDSA algorithms
        if ("EC".equals(keyAlgorithm) || "ECDSA".equals(keyAlgorithm)) {
            return signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1") ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256") ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384") ||
                    signatureAlgorithm.equals("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
        }

        // For any other algorithm, try exact match
        return keyAlgorithm.equalsIgnoreCase(extractKeyAlgorithmFromURI(signatureAlgorithm));
    }

    /**
     * Extract key algorithm name from signature algorithm URI
     */
    private String extractKeyAlgorithmFromURI(String uri) {
        if (uri.contains("rsa")) return "RSA";
        if (uri.contains("dsa")) return "DSA";
        if (uri.contains("ecdsa")) return "EC";
        return "";
    }

    /**
     * Simple KeySelectorResult implementation
     */
    private record SimpleKeySelector(Key key) implements KeySelectorResult {

        @Override
        public Key getKey() {
            return key;
        }
    }
}
