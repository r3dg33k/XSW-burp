package burp.utilities.helpers;

public enum EncodingType {
    UTF_7("UTF-7"),
    UTF_8("UTF-8"),
    UTF_16("UTF-16"),
    UTF_16BE("UTF-16BE"),
    UTF_16LE("UTF-16LE");

    private final String encoding;

    EncodingType(String encoding) {
        this.encoding = encoding;
    }

    public static EncodingType fromString(String encoding) {
        for (EncodingType type : EncodingType.values()) {
            if (type.encoding.equalsIgnoreCase(encoding)) {
                return type;
            }
        }
        return null;
    }

    public String getEncoding() {
        return encoding;
    }
}
