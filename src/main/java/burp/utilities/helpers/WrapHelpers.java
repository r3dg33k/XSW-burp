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

    public static byte[] encode(EncodingType encodingType, byte[] code) {

        switch (encodingType) {
            /**
             * Exploiting XXE via UTF-7 encoding
             * If the parser is configured to accept multiple character encodings,
             * we could essentially send our malicious payload encoded in UTF-7 instead of the UTF-8 character set:
             *
             * <?xml version="1.0" encoding="UTF-7"?>
             * This approach can help us bypass several input validation restrictions,
             * especially systems that filter based on blacklisted keywords to prevent XXE injection attacks.
             *
             * TIP! Remember to include the XML prolog in your payload and set the encoding to "UTF-7"!
             */
            case UTF_7:
                byte[] prolog = "<?xml version=\"1.0\" encoding=\"UTF-7\"?>".getBytes(StandardCharsets.UTF_8);
                byte[] combined = new byte[prolog.length + code.length];
                System.arraycopy(prolog, 0, combined, 0, prolog.length);
                System.arraycopy(code, 0, combined, prolog.length, code.length);

                try {
                    Charset charset = Charset.forName("UTF-7");
                    ByteBuffer byteBuffer = charset.encode(new String(combined, StandardCharsets.UTF_8));
                    byte[] ba = new byte[byteBuffer.remaining()];
                    byteBuffer.get(ba, 0, ba.length);
                    code = ba;
                } catch (Exception e) {
                    ByteBuffer result = encodeUtf7(ByteBuffer.wrap(combined));
                    code = new byte[result.remaining()];
                    result.get(code);
                }
                break;
            case UTF_8:
                byte[] utf8Prolog = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".getBytes(StandardCharsets.UTF_8);
                byte[] utf8Combined = new byte[utf8Prolog.length + code.length];
                System.arraycopy(utf8Prolog, 0, utf8Combined, 0, utf8Prolog.length);
                System.arraycopy(code, 0, utf8Combined, utf8Prolog.length, code.length);
                code = utf8Combined;
                break;
            case UTF_16:
                byte[] utf16Prolog = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>".getBytes(StandardCharsets.UTF_8);
                byte[] utf16Combined = new byte[utf16Prolog.length + code.length];
                System.arraycopy(utf16Prolog, 0, utf16Combined, 0, utf16Prolog.length);
                System.arraycopy(code, 0, utf16Combined, utf16Prolog.length, code.length);
                code = new String(utf16Combined, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_16);
                break;
            case UTF_16BE:
                byte[] utf16beProlog = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>".getBytes(StandardCharsets.UTF_8);
                byte[] utf16beCombined = new byte[utf16beProlog.length + code.length];
                System.arraycopy(utf16beProlog, 0, utf16beCombined, 0, utf16beProlog.length);
                System.arraycopy(code, 0, utf16beCombined, utf16beProlog.length, code.length);
                code = new String(utf16beCombined, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_16BE);
                break;
            case UTF_16LE:
                byte[] utf16leProlog = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>".getBytes(StandardCharsets.UTF_8);
                byte[] utf16leCombined = new byte[utf16leProlog.length + code.length];
                System.arraycopy(utf16leProlog, 0, utf16leCombined, 0, utf16leProlog.length);
                System.arraycopy(code, 0, utf16leCombined, utf16leProlog.length, code.length);
                code = new String(utf16leCombined, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_16LE);
                break;
            default:
                break;
        }
        return code;
    }

    public static ByteBuffer encodeUtf7(ByteBuffer input) {
        StringBuilder sb = new StringBuilder();
        for (byte c : input.array()) {
            if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)) {
                sb.append((char) c);
            } else {
                byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_16BE);
                String base64 = Base64.getEncoder().encodeToString(bytes);
                sb.append('+').append(base64.replace("=", "")).append('-');
            }
        }
        return ByteBuffer.wrap(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates a list of SAML response documents, each containing a single canary variation.
     * Instead of one document with all fields set to canary, this creates separate documents
     * where only one field per document contains the canary value.
     *
     * @param authnRequest The SAML authentication request to build responses from
     * @param canary       The canary string to inject into each variation
     * @return List of Documents, each with a single canary variation
     */
    public static List<Document> generateCanaryVariations(SAMLAuthnRequestDocument authnRequest, String canary) {
        List<Document> variations = new ArrayList<>();

        // Define all the variations as lambdas that apply one specific canary field
        List<java.util.function.Function<SAMLResponseBuilder, SAMLResponseBuilder>> builderVariations = List.of(
                builder -> builder.withResponseID(canary),
                builder -> builder.withAssertionID(canary),
                builder -> builder.withIssuer(canary),
                builder -> builder.withDestination(canary),
                builder -> builder.withAudience(canary),
                builder -> builder.withNameId(canary),
                builder -> builder.withNameIdFormat(canary),
                builder -> builder.withSessionIndex(canary),
                builder -> builder.withStatusCode(canary),
                builder -> builder
                        .withStatusCode(StatusCode.REQUESTER.getStatusCode())
                        .withStatusMessage(canary),
                builder -> builder
                        .withStatusCode(StatusCode.REQUESTER.getStatusCode())
                        .withStatusDetail(canary),
                builder -> builder.withAuthInstant(canary),
                builder -> builder.withIssueInstant(canary),
                builder -> builder.withNotBefore(canary),
                builder -> builder.withNotOnOrAfter(canary)
        );
        // Generate a document for each variation
        for (var variation : builderVariations) {
            try {
                SAMLResponseBuilder builder = new SAMLResponseBuilder(authnRequest)
                        .withNameId(canary)
                        .withDefaultAttributes();

                // Apply only this specific variation
                builder = variation.apply(builder);

                Document doc = builder.build();
                variations.add(doc);
            } catch (Exception ignored) {
            }
        }

        return variations;
    }
}
