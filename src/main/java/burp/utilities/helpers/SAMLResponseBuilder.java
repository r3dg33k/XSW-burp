package burp.utilities.helpers;

import burp.models.SAMLAuthnRequestDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static burp.utilities.helpers.Constants.*;

public class SAMLResponseBuilder {

    private final XMLHelpers xmlHelpers;
    private final Map<String, String> attributes = new HashMap<>();
    private final String dsPrefix = "ds";
    private final String xsPrefix = "xs";
    private final String xsiPrefix = "xsi";
    private String saml2Prefix = "saml";
    private String saml2pPrefix = "samlp";
    // Response
    private String ResponseID;
    private String Version;
    private String Destination;
    private String InResponseTo;
    private String Recipient; // extract but never use for now
    private String Issuer;
    private String statusCode = STATUS_CODE_SUCCESS;
    private String StatusMessage;
    private String StatusDetail;
    // Assertion
    private String AssertionID;
    private String SPNameQualifier;
    private String NameIdFormat;
    private String NameId;
    private String SubjectConfirmationMethod;
    private String Audience;
    private String sessionIndex;
    private String SubjectLocality;
    private String AuthnContextClassRef;
    private String issueInstant = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    private String authInstant = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    private String notBefore = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    private String notOnOrAfter = DateTimeFormatter.ISO_INSTANT.format(Instant.now().plusSeconds(3600));

    private Node signature;
    private boolean useRecipient = true;

    /**
     * Create new SAMLResponse document
     *
     * @param destination
     * @param issuer
     * @param nameId
     */
    public SAMLResponseBuilder(String destination, String issuer, String nameId) {
        this.xmlHelpers = XMLHelpers.getInstance();
        this.Destination = destination;
        this.Recipient = destination;
        this.Issuer = issuer;
        this.Audience = issuer;
        this.NameId = nameId;
    }

    public SAMLResponseBuilder(SAMLAuthnRequestDocument authnRequest) {
        this.xmlHelpers = XMLHelpers.getInstance();

        String requestId = authnRequest.getID();
        if (requestId != null) {
            this.InResponseTo = requestId;
        }

        String version = authnRequest.getVersion();
        if (version != null) {
            this.Version = version;
        }

        String acsUrl = authnRequest.getAssertionConsumerServiceURL();
        if (acsUrl != null) {
            this.Destination = acsUrl;
            this.Recipient = acsUrl;
        }

        String issuer = authnRequest.getIssuer();
        if (issuer != null) {
            this.Audience = issuer;
        }

        List<String> refs = authnRequest.getRequestedAuthnContextClassRefs();
        if (!refs.isEmpty()) {
            this.AuthnContextClassRef = refs.getFirst();
        }

        Map<String, String> policy = authnRequest.getNameIDPolicy();
        if (!policy.isEmpty() && policy.get("Format") != null) {
            this.NameIdFormat = policy.get("Format");
        }
    }

    public SAMLResponseBuilder withResponseID(String id) {
        this.ResponseID = id;
        return this;
    }

    public SAMLResponseBuilder withAssertionID(String id) {
        this.AssertionID = id;
        return this;
    }

    public SAMLResponseBuilder withIssuer(String issuer) {
        this.Issuer = issuer;
        return this;
    }

    public SAMLResponseBuilder withDestination(String destination) {
        this.Destination = destination;
        return this;
    }

    public SAMLResponseBuilder withRecipient(String recipient) {
        this.Recipient = recipient;
        this.useRecipient = true;
        return this;
    }

    public SAMLResponseBuilder useRecipient(boolean useRecipient) {
        this.useRecipient = useRecipient;
        return this;
    }

    public SAMLResponseBuilder withAudience(String audience) {
        this.Audience = audience;
        return this;
    }

    public SAMLResponseBuilder withNameId(String nameId) {
        this.NameId = nameId;
        return this;
    }

    public SAMLResponseBuilder withNameIdFormat(String nameIdFormat) {
        this.NameIdFormat = nameIdFormat;
        return this;
    }

    public SAMLResponseBuilder withSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
        return this;
    }

    public SAMLResponseBuilder withSubjectLocality(String collaborator) {
        this.SubjectLocality = collaborator;
        return this;
    }

    public SAMLResponseBuilder withAttribute(String name, String value) {
        this.attributes.put(name, value);
        return this;
    }

    public SAMLResponseBuilder withDefaultAttributes() {
        this.attributes.putAll(DEFAULT_ATTRIBUTES);
        return this;
    }

    public SAMLResponseBuilder withStatusCode(String statusCode) {
        this.statusCode = statusCode;
        return this;
    }

    public SAMLResponseBuilder withStatusMessage(String statusMessage) {
        this.StatusMessage = statusMessage;
        return this;
    }

    public SAMLResponseBuilder withStatusDetail(String statusDetail) {
        this.StatusDetail = statusDetail;
        return this;
    }

    public SAMLResponseBuilder withIssueInstant(String issueInstant) {
        this.issueInstant = issueInstant;
        return this;
    }

    public SAMLResponseBuilder withAuthInstant(String authInstant) {
        this.authInstant = authInstant;
        return this;
    }

    public SAMLResponseBuilder withNotBefore(String notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public SAMLResponseBuilder withNotOnOrAfter(String notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
        return this;
    }

    public SAMLResponseBuilder withSAML2(String prefix) {
        this.saml2Prefix = prefix;
        return this;
    }

    public SAMLResponseBuilder withSAML2p(String prefix) {
        this.saml2pPrefix = prefix;
        return this;
    }

    public SAMLResponseBuilder withSignature(Node signature) {
        this.signature = signature;
        return this;
    }

    public Document build() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = xmlHelpers.getDBF();
        if (dbf == null) throw new ParserConfigurationException();

        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();

        Element response = createResponseElement(doc);
        doc.appendChild(response);

        Element status = createStatusElement(doc);
        response.appendChild(status);

        Element assertion = createAssertionElement(doc);
        response.appendChild(assertion);

        return doc;
    }

    private Element createResponseElement(Document doc) {
        Element response = doc.createElementNS(SAML2P_NAMESPACE, saml2pPrefix + ":Response");

        response.setAttributeNS(
                XMLNS,
                "xmlns:" + saml2Prefix,
                SAML2_NAMESPACE
        );
        response.setAttributeNS(
                XMLNS,
                "xmlns:" + saml2pPrefix,
                SAML2P_NAMESPACE
        );

        response.setAttribute("ID", Objects.requireNonNullElseGet(ResponseID, () -> "_" + UUID.randomUUID()));
        response.setAttribute("Version", Objects.requireNonNullElse(Version, "2.0"));
        response.setAttribute("IssueInstant", issueInstant);
        // Optional
        response.setAttribute("InResponseTo", Objects.requireNonNullElseGet(InResponseTo, () -> UUID.randomUUID().toString()));
        response.setAttribute("Destination", Objects.requireNonNullElse(Destination, "Destination"));

        Element issuerElement = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Issuer");
        issuerElement.setTextContent(Objects.requireNonNullElse(Issuer, "issuer"));
        response.appendChild(issuerElement);

        return response;
    }

    private Element createStatusElement(Document doc) {
        Element status = doc.createElementNS(SAML2P_NAMESPACE, saml2pPrefix + ":Status");
        Element statusCode = doc.createElementNS(SAML2P_NAMESPACE, saml2pPrefix + ":StatusCode");
        statusCode.setAttribute("Value", this.statusCode);
        status.appendChild(statusCode);
        if (this.StatusMessage != null) {
            Element statusMessage = doc.createElementNS(SAML2P_NAMESPACE, saml2pPrefix + ":StatusMessage");
            statusMessage.setTextContent(this.StatusMessage);
            status.appendChild(statusMessage);
        }
        if (this.StatusDetail != null) {
            Element statusDetail = doc.createElementNS(SAML2P_NAMESPACE, saml2pPrefix + ":StatusDetail");
            Element cause = doc.createElement("Cause");
            cause.setTextContent(this.StatusDetail);
            statusDetail.appendChild(cause);
            status.appendChild(statusDetail);
        }
        return status;
    }

    private Element createAssertionElement(Document doc) {
        Element assertion = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Assertion");
        assertion.setAttribute("ID", Objects.requireNonNullElseGet(AssertionID, () -> "_" + UUID.randomUUID()));
        assertion.setAttribute("Version", Objects.requireNonNullElse(Version, "2.0"));
        assertion.setAttribute("IssueInstant", issueInstant);

        Element issuerElement = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Issuer");
        issuerElement.setTextContent(Objects.requireNonNullElse(Issuer, "issuer"));
        assertion.appendChild(issuerElement);

        if (signature != null) {
            String referenceURI = null;
            Node imported = doc.importNode(signature, true);
            assertion.appendChild(imported);

            NodeList referenceList = ((Element) imported).getElementsByTagNameNS("*", "Reference");
            Element referenceElement = (Element) referenceList.item(0);
            if (referenceElement != null && referenceElement.hasAttribute("URI")) {
                referenceURI = referenceElement.getAttribute("URI").substring(1);
            }

            assertion.setAttribute("ID", referenceURI);
        }
        Element subject = createSubjectElement(doc);
        assertion.appendChild(subject);

        Element conditions = createConditionsElement(doc);
        assertion.appendChild(conditions);

        Element authnStatement = createAuthnStatementElement(doc);
        assertion.appendChild(authnStatement);

        Element attributeStatement = createAttributeStatementElement(doc);
        assertion.appendChild(attributeStatement);
        return assertion;
    }

    private Element createSubjectElement(Document doc) {
        Element subject = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Subject");

        Element nameIdElement = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":NameID");
        nameIdElement.setAttribute("Format", Objects.requireNonNullElse(NameIdFormat, NAME_ID_FORMAT));
        nameIdElement.setTextContent(NameId);
        subject.appendChild(nameIdElement);

        Element subjectConfirmation = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", Objects.requireNonNullElse(SubjectConfirmationMethod, SUBJECT_CONFIRMATION));

        Element subjectConfirmationData = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter", notOnOrAfter);
        if (this.Recipient != null && this.useRecipient) {
            subjectConfirmationData.setAttribute("Recipient", Recipient);
        }
        subjectConfirmationData.setAttribute("InResponseTo", Objects.requireNonNullElseGet(InResponseTo, () -> UUID.randomUUID().toString()));

        subjectConfirmation.appendChild(subjectConfirmationData);
        subject.appendChild(subjectConfirmation);

        return subject;
    }

    private Element createConditionsElement(Document doc) {
        Element conditions = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Conditions");
        conditions.setAttribute("NotBefore", notBefore);
        conditions.setAttribute("NotOnOrAfter", notOnOrAfter);

        if (Audience != null) {
            Element audienceRestriction = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AudienceRestriction");
            Element audience = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Audience");
            audience.setTextContent(Audience);
            audienceRestriction.appendChild(audience);
            conditions.appendChild(audienceRestriction);
        }

        return conditions;
    }

    private Element createAuthnStatementElement(Document doc) {
        Element authnStatement = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AuthnStatement");
        authnStatement.setAttribute("AuthnInstant", authInstant);

        Element authnContext = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AuthnContext");
        Element authnContextClassRef = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AuthnContextClassRef");
        authnContextClassRef.setTextContent(Objects.requireNonNullElse(AuthnContextClassRef, AREF_PASSWORD));
        authnContext.appendChild(authnContextClassRef);
        if (this.SubjectLocality != null) {
            Element subjectLocality = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":SubjectLocality");
            subjectLocality.setAttribute("DNSName", this.SubjectLocality);
            authnStatement.appendChild(subjectLocality);
        }
        authnStatement.appendChild(authnContext);

        return authnStatement;
    }

    private Element createAttributeStatementElement(Document doc) {
        Element attributeStatement = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AttributeStatement");

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            Element attribute = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":Attribute");
            attribute.setAttribute("Name", entry.getKey());
            attribute.setAttribute("NameFormat", entry.getValue());

            Element attributeValue = doc.createElementNS(SAML2_NAMESPACE, saml2Prefix + ":AttributeValue");
            attributeValue.setAttributeNS(
                    XMLNS,
                    "xmlns:" + xsiPrefix,
                    XSI_NAMESPACE
            );
            attributeValue.setAttributeNS(
                    XMLNS,
                    "xmlns:" + xsPrefix,
                    XS_NAMESPACE
            );
            attributeValue.setAttributeNS(XSI_NAMESPACE, xsiPrefix + ":type", xsPrefix + ":string");

            String name = Objects.requireNonNullElse(this.NameId, "administrator");
            String attr = name;
            if (CLAIMS.containsKey(entry.getKey())) attr = CLAIMS.get(entry.getKey()).replace(EMAIL_PLACEHOLDER, name);
            attributeValue.setTextContent(attr);
            attribute.appendChild(attributeValue);

            attributeStatement.appendChild(attribute);
        }

        return attributeStatement;
    }
}