package burp.models;

import burp.utilities.helpers.CertificateHelper;

public record BurpCertificateExtension(String oid, boolean isCritical, byte[] extensionValue) {

    public String toString() {
        return oid + (isCritical ? " (Critical): " : " (Not critical): ") + CertificateHelper.byteArrayToHex(extensionValue);
    }
}
