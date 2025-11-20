package burp.utilities.helpers;

import burp.models.SAMLAuthnRequestDocument;
import org.w3c.dom.Document;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class WrapHelpers {

    public static final String ISSUER_PLACEHOLDER = "ISSUER_PLACEHOLDER";
    private static final String OKTA_FORMAT = "https://%s/FederationMetadata/2007-06/%s/FederationMetadata.xml";
    private static final String AUTH0_FORMAT = "https://%s/samlp/metadata/%s";
    private static final String ONELOGIN_FORMAT = "https://%s/saml/metadata/%s";
    private static final String PINGFEDERATE_FORMAT = "https://%s/pf/federation_metadata.ping?PartnerSpId=" + ISSUER_PLACEHOLDER;

    public static List<String> DEFAULT_METADATA = List.of(
            "/FederationMetadata/2007-06/FederationMetadata.xml",
            "/saml/metadata.xml",
            "/metadata.xml",
            "/saml/metadata",
            "/metadata"
    );

    public static String getMetadataURL(String request) {
        try {
            URI uri = new URI(request);
            String host = uri.getHost();
            if (host.isEmpty()) return null;
            String[] parts = uri.getPath().split("/");
            if (parts.length == 0) return null;

            // Okta: detect by path pattern /app/.../sso/saml (works with both *.okta.com and custom domains)
            if (parts.length == 6 && "app".equals(parts[1]) && "sso".equals(parts[4]) && "saml".equals(parts[5])) {
                return String.format(OKTA_FORMAT, host, parts[3]);
            }
            // Auth0
            else if (host.endsWith(".auth0.com") && parts.length == 3) {
                return String.format(AUTH0_FORMAT, host, parts[2]);
            }
            // OneLogin
            else if (host.endsWith(".onelogin.com")) {
                if (parts.length == 4) {
                    return String.format(ONELOGIN_FORMAT, host, parts[3]);
                } else if (parts.length == 6) {
                    return String.format(ONELOGIN_FORMAT, host, parts[5]);
                }
            }
            // PingFederate: detect by /idp/SSO.saml2 pattern
            else if (parts.length >= 3 &&
                    ("idp".equals(parts[1]) && "SSO.saml2".equals(parts[2]))) {
                return String.format(PINGFEDERATE_FORMAT, host);
            }
        } catch (URISyntaxException e) {
            return null;
        }
        return null;
    }
}
