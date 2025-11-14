package burp.utilities.helpers;

// 3.2.2.2 Element <StatusCode>
public enum StatusCode {
    SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
    REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester"),
    RESPONDER("urn:oasis:names:tc:SAML:2.0:status:Responder");

    private final String code;

    StatusCode(String code) {
        this.code = code;
    }

    public static StatusCode fromString(String code) {
        for (StatusCode statusCode : StatusCode.values()) {
            if (statusCode.code.equalsIgnoreCase(code)) {
                return statusCode;
            }
        }
        return null;
    }

    public String getStatusCode() {
        return code;
    }
}
