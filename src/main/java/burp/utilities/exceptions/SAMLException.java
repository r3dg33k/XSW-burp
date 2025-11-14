package burp.utilities.exceptions;

public class SAMLException extends Exception {
    public SAMLException(String message) {
        super(message);
    }

    public SAMLException(Exception e) {
        super(e);
    }
}
