package burp.utilities.helpers;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

public class Constants {
    public static final String NAME_ID = "administrator@gitlab.lab.local";
    public static final String XML = "http://www.w3.org/XML/1998/namespace";
    public static final String XMLNS = "http://www.w3.org/2000/xmlns/";
    public static final String SAML2P_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String SAML2_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAML2_METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";
    public static final String DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

    public static final String XS_NAMESPACE = "http://www.w3.org/2001/XMLSchema";
    public static final String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance";

    public static final String STATUS_CODE_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    public static final String AREF_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    public static final String SUBJECT_CONFIRMATION = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    public static final String NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String URI_ATTRNAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    public static final String BASIC_ATTRNAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
    public static final String UNDEFINED_ATTRNAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    public static final String EMAIL_PLACEHOLDER = "EMAIL_PLACEHOLDER";

    public static final String HTTP_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    static Map<String, String> CLAIMS = new HashMap<>();
    static Map<String, String> DEFAULT_ATTRIBUTES = Map.of(
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", URI_ATTRNAME_FORMAT,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", URI_ATTRNAME_FORMAT,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", URI_ATTRNAME_FORMAT,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", URI_ATTRNAME_FORMAT
    );

    static {
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", EMAIL_PLACEHOLDER);
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Doge");
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Doge");
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", EMAIL_PLACEHOLDER);
        CLAIMS.put("http://schemas.xmlsoap.org/claims/CommonName", "Doge");
        CLAIMS.put("http://schemas.xmlsoap.org/claims/EmailAddress", EMAIL_PLACEHOLDER);
        CLAIMS.put("http://schemas.xmlsoap.org/claims/Group", "Administrators");
        CLAIMS.put("http://schemas.xmlsoap.org/claims/UPN", EMAIL_PLACEHOLDER);
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Administrator");
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Doge");
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier", UUID.randomUUID().toString());
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "okta|4d09e4d09e");
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "password");
        CLAIMS.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid", "S-1-5-" + new Random().nextInt(999999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid", "S-1-5-" + new Random().nextInt(999999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid", "S-1-5-" + new Random().nextInt(999999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", "S-1-5-32-" + new Random().nextInt(9999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid", "S-1-5-21-" + new Random().nextInt(99999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", "S-1-5-21-" + new Random().nextInt(99999));
        CLAIMS.put("http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", "DOMAIN\\4d09e4d09e");
    }

}
