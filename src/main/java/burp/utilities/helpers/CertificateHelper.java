package burp.utilities.helpers;

import burp.models.BurpCertificate;
import burp.models.BurpCertificateBuilder;
import burp.models.BurpCertificateExtension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

public class CertificateHelper {

    public static String addHexColons(String input) {
        return input.replaceAll("..(?!$)", "$0:");
    }

    public static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll(":", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bigIntegerToHexString(BigInteger bigInteger) {
        return addHexColons(bigInteger.toString(16));
    }

    public static String bigIntegerToHexString(String bigInteger) {
        return bigIntegerToHexString(new BigInteger(bigInteger));
    }

    public static BigInteger hexStringToBigInteger(String hexString) {
        return new BigInteger(hexString.replaceAll(":", ""), 16);
    }

    /**
     * Reads a Date as a String and returns a Date object.
     *
     * @param date Date as a String. Supported formats are
     *             "MMM d HH:mm:ss yyy ZZZ" (Eg. Aug 15 10:56:49 2012 GMT) and
     *             "EEE MMM d HH:mm:ss ZZZ yyy" (Eg. Thu Mar 26 01:00:00 CET
     *             2015)
     * @return Date object
     * @throws ParseException           if input date cannot be parsed
     * @throws IllegalArgumentException If input date format is not supported
     */
    public static Date stringToDate(String date) throws ParseException, IllegalArgumentException {
        SimpleDateFormat simpleDateFormat;
        Pattern pattern;

        Locale.setDefault(Locale.US); // The input date is in english

        // Format: MMM d HH:mm:ss yyy ZZZ (Eg. Aug 15 10:56:49 2012 GMT)
        pattern = Pattern.compile("[A-Z][a-z]{2} [0-9]{1,2} ([0-9]{2}:){1,2}[0-9]{2} [0-9]{4} [A-Z]{3}");
        if (pattern.matcher(date).matches()) {
            simpleDateFormat = new SimpleDateFormat("MMM d HH:mm:ss yyy ZZZ");
            return simpleDateFormat.parse(date);
        }
        // Format: EEE MMM d HH:mm:ss ZZZ yyy (Eg. Thu Mar 26 01:00:00 CET 2015)
        pattern = Pattern.compile("[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{1,2} ([0-9]{2}:){1,2}[0-9]{2} [A-Z]{3,4} [0-9]{4}");
        if (pattern.matcher(date).matches()) {
            simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss ZZZ yyyy");
            return simpleDateFormat.parse(date);
        }

        throw new IllegalArgumentException("Unknown date format.");
    }

    /**
     * Returns a hexadecimal representation of a byte array.
     *
     * @param bytes byte array to parse
     * @return String with hex numbers of the byte array
     */
    public static String byteArrayToHex(byte[] bytes) {
        // http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Converts the Object x509CertificateHolder to X509Certificate using the
     * Bouncy Castle library.
     *
     * @param x509CertificateHolder Certificate to convert.
     * @return Converted certificate
     * @throws CertificateException if the certifiate cannot be converted
     */
    public static X509Certificate x509CertificateHolderToX509Certificate(X509CertificateHolder x509CertificateHolder) throws CertificateException {
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);

    }

    /**
     * Returns the ASCII Values of a byte string.
     *
     * @param hexString to convert into an ASCII string
     * @return ASCII representation of the input string
     */
    public static String hexBytesToString(String hexString) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * Returns the ASCII Values of a byte array.
     *
     * @param bytes to convert into an ASCII string.
     * @return ASCII representation of the input byte array.
     */
    public static String byteArrayToString(byte[] bytes) {
        return hexBytesToString(byteArrayToHex(bytes));
    }

    /**
     * Copy all X.509v3 general information and all extensions 1:1 from one
     * source certificat to one destination certificate.
     *
     * @param certificate            with the original information
     * @param burpCertificateBuilder for generating the destination certificate
     */
    private static void cloneProperties(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder) {
        burpCertificateBuilder.setVersion(certificate.getVersionNumber());
        burpCertificateBuilder.setSerial(certificate.getSerialNumberBigInteger());
        if (certificate.getPublicKeyAlgorithm().equals("RSA")) {
            burpCertificateBuilder.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        } else {
            burpCertificateBuilder.setSignatureAlgorithm("SHA256withRSA");
        }
        burpCertificateBuilder.setIssuer(certificate.getIssuer());
        burpCertificateBuilder.setNotAfter(certificate.getNotAfter());
        burpCertificateBuilder.setNotBefore(certificate.getNotBefore());
        burpCertificateBuilder.setKeySize(certificate.getKeySize());

        for (BurpCertificateExtension extension : certificate.getAllExtensions()) {
            burpCertificateBuilder.addExtension(extension);
        }
    }

    /**
     * Clone a certificate from one source certificate. New private key material
     * is generated.
     *
     * @param certificate            to clone
     * @param burpCertificateBuilder for generating the new cloned certificate
     * @return cloned certificate
     */
    public static BurpCertificate cloneCertificate(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder) {
        cloneProperties(certificate, burpCertificateBuilder);

        BurpCertificate burpCertificate;
        try {
            burpCertificate = burpCertificateBuilder.generateSelfSignedCertificate();
            burpCertificate.setSource("Cloned");
            return burpCertificate;
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Clone a certificate and sign it with another private key from an issuer.
     *
     * @param certificate            to clone
     * @param burpCertificateBuilder for the cloned certificate
     * @param issuerCertificate      for signing the new certificate
     * @return cloned certificate
     */
    public BurpCertificate cloneAndSignCertificate(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder, BurpCertificate issuerCertificate) {
        cloneProperties(certificate, burpCertificateBuilder);

        try {
            if (!issuerCertificate.hasPrivateKey()) {
                throw new Exception("No private key found.");
            }
        } catch (Exception ignored) {
        }

        BurpCertificate burpCertificate;
        try {
            burpCertificate = burpCertificateBuilder.generateCertificate(issuerCertificate);
            burpCertificate.setSource("Cloned and signed by cloned " + issuerCertificate.getSubject());
            return burpCertificate;
        } catch (Exception ignored) {

        }
        return null;
    }

    /**
     * Clone whole certificate chain
     *
     * @param certificateChain to clone
     * @return List of cloned certificates. According to RFC 5246: Next
     * Certificate must sign previous.
     */
    public List<BurpCertificate> cloneCertificateChain(List<BurpCertificate> certificateChain) {
        List<BurpCertificate> certificates = new LinkedList<>();

        // b/c of RFC 5246 I generate them in reverse order
        Collections.reverse(certificateChain);
        BurpCertificate currentCertificate;
        BurpCertificate previousCertificate = null;
        for (BurpCertificate c : certificateChain) {
            if (previousCertificate == null) { // self-sign
                currentCertificate = cloneCertificate(c, new BurpCertificateBuilder(c.getSubject()));
            } else {
                currentCertificate = cloneAndSignCertificate(c, new BurpCertificateBuilder(c.getSubject()), previousCertificate);
            }
            certificates.add(currentCertificate);
            previousCertificate = currentCertificate;
        }
        Collections.reverse(certificates); // Restore original order
        return certificates;
    }
}