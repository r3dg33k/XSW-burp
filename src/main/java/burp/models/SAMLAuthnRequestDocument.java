package burp.models;

import burp.utilities.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static burp.utilities.helpers.Constants.SAML2P_NAMESPACE;
import static burp.utilities.helpers.Constants.SAML2_NAMESPACE;

public class SAMLAuthnRequestDocument {

    private final Document document;
    private final Element root;
    private final XMLHelpers xmlHelpers;

    public SAMLAuthnRequestDocument(Document document) {
        this.document = document;
        this.root = document.getDocumentElement();
        this.xmlHelpers = XMLHelpers.getInstance();
    }

    public Element getFirstChild() {
        return root;
    }

    /**
     * Extracts the ID from the AuthnRequest
     *
     * @return ID or null if not found
     */
    public String getID() {
        String id = xmlHelpers.getAttributeValueByName(root, "ID");
        return id.isEmpty() ? null : id;
    }

    /**
     * Extracts the Version from the AuthnRequest
     *
     * @return Version or null if not found
     */
    public String getVersion() {
        String version = xmlHelpers.getAttributeValueByName(root, "Version");
        return version.isEmpty() ? null : version;
    }

    /**
     * Extracts the IssueInstant from the AuthnRequest
     *
     * @return IssueInstant or null if not found
     */
    public String getIssueInstant() {
        String issueInstant = xmlHelpers.getAttributeValueByName(root, "IssueInstant");
        return issueInstant.isEmpty() ? null : issueInstant;
    }

    /**
     * Extracts the OPTIONAL Destination from the AuthnRequest
     *
     * @return Destination or null if not found
     */
    public String getDestination() {
        String destination = xmlHelpers.getAttributeValueByName(root, "Destination");
        return destination.isEmpty() ? null : destination;
    }

    /**
     * Extracts the OPTIONAL Issuer from the AuthnRequest
     *
     * @return Issuer value or null if not found
     */
    public String getIssuer() {
        String issuer = xmlHelpers.getIssuer(document);
        return issuer.isEmpty() ? null : issuer;
    }

    /**
     * Extracts the OPTIONAL Extensions node from the AuthnRequest
     *
     * @return Extensions node value or null if not found
     */
    public Node getExtensions() {
        NodeList extensions = xmlHelpers.getExtensions(document);
        if (extensions.getLength() > 0) {
            return extensions.item(0);
        }
        return null;
    }

    /**
     * Extracts the ProtocolBinding from the AuthnRequest
     * Make sure that HTTP_POST_BINDING is returned
     *
     * @return ProtocolBinding or null if not found
     */
    public String getProtocolBinding() {
        String binding = xmlHelpers.getAttributeValueByName(root, "ProtocolBinding");
        return binding.isEmpty() ? null : binding;
    }

    /**
     * Extracts the AssertionConsumerServiceURL from the AuthnRequest
     *
     * @return AssertionConsumerServiceURL or null if not found
     */
    public String getAssertionConsumerServiceURL() {
        String acsUrl = xmlHelpers.getAttributeValueByName(root, "AssertionConsumerServiceURL");
        return acsUrl.isEmpty() ? null : acsUrl;
    }

    /**
     * Extracts the AssertionConsumerServiceIndex from the AuthnRequest
     *
     * @return AssertionConsumerServiceIndex or null if not found
     */
    public String getAssertionConsumerServiceIndex() {
        String index = xmlHelpers.getAttributeValueByName(root, "AssertionConsumerServiceIndex");
        return index.isEmpty() ? null : index;
    }

    /**
     * Checks if the AuthnRequest has IsPassive set to true
     *
     * @return true if IsPassive is "true", false otherwise
     */
    public boolean isPassive() {
        String isPassive = xmlHelpers.getAttributeValueByName(root, "IsPassive");
        return "true".equalsIgnoreCase(isPassive);
    }

    /**
     * Checks if the AuthnRequest has ForceAuthn set to true
     *
     * @return true if ForceAuthn is "true", false otherwise
     */
    public boolean isForceAuthn() {
        String forceAuthn = xmlHelpers.getAttributeValueByName(root, "ForceAuthn");
        return "true".equalsIgnoreCase(forceAuthn);
    }

    /**
     * Extracts an X509 certificate from the AuthnRequest as base64 string
     *
     * @return Base64 encoded certificate, null if nothing found
     */
    public String getX509Certificate() {
        return xmlHelpers.getCertificate(root);
    }

    /**
     * Gets the Signature element if exists
     *
     * @return Signature element or null if not found
     */
    public Element getSignature() {
        NodeList signatures = xmlHelpers.getSignatures(document);
        return signatures.getLength() > 0 ? (Element) signatures.item(0) : null;
    }

    /**
     * Checks if the AuthnRequest is signed
     *
     * @return true if Signature element exists
     */
    public boolean isSigned() {
        return getSignature() != null;
    }

    /**
     * Extracts NameIDPolicy information from the AuthnRequest
     *
     * @return Map containing "Format" and "AllowCreate" if present, empty map otherwise
     */
    public Map<String, String> getNameIDPolicy() {
        Map<String, String> nameIDPolicy = new HashMap<>();

        NodeList nameIDPolicyNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "NameIDPolicy");
        if (nameIDPolicyNodes.getLength() > 0) {
            Element nameIDPolicyElement = (Element) nameIDPolicyNodes.item(0);

            String format = xmlHelpers.getAttributeValueByName(nameIDPolicyElement, "Format");
            if (!format.isEmpty()) {
                nameIDPolicy.put("Format", format);
            }

            String allowCreate = xmlHelpers.getAttributeValueByName(nameIDPolicyElement, "AllowCreate");
            if (!allowCreate.isEmpty()) {
                nameIDPolicy.put("AllowCreate", allowCreate);
            }
        }

        return nameIDPolicy;
    }

    /**
     * Extracts AuthnContextClassRef elements from RequestedAuthnContext
     *
     * @return List of AuthnContextClassRef URIs, empty list if none found
     */
    public List<String> getRequestedAuthnContextClassRefs() {
        List<String> classRefs = new ArrayList<>();

        NodeList requestedAuthnContextNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "RequestedAuthnContext");
        if (requestedAuthnContextNodes.getLength() > 0) {
            Element requestedAuthnContext = (Element) requestedAuthnContextNodes.item(0);
            NodeList classRefNodes = requestedAuthnContext.getElementsByTagNameNS(SAML2_NAMESPACE, "AuthnContextClassRef");

            for (int i = 0; i < classRefNodes.getLength(); i++) {
                String classRef = classRefNodes.item(i).getTextContent();
                if (classRef != null && !classRef.trim().isEmpty()) {
                    classRefs.add(classRef.trim());
                }
            }
        }

        return classRefs;
    }

    /**
     * Extracts the Comparison attribute from RequestedAuthnContext
     *
     * @return Comparison attribute value or null if not found
     */
    public String getRequestedAuthnContextComparison() {
        NodeList requestedAuthnContextNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "RequestedAuthnContext");
        if (requestedAuthnContextNodes.getLength() > 0) {
            Element requestedAuthnContext = (Element) requestedAuthnContextNodes.item(0);
            String comparison = xmlHelpers.getAttributeValueByName(requestedAuthnContext, "Comparison");
            return comparison.isEmpty() ? null : comparison;
        }
        return null;
    }

    /**
     * Extracts the ProxyCount attribute from Scoping element
     *
     * @return ProxyCount attribute value or null if not found
     */
    public String getScopingProxyCount() {
        NodeList scopingNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "Scoping");
        if (scopingNodes.getLength() > 0) {
            Element scoping = (Element) scopingNodes.item(0);
            String proxyCount = xmlHelpers.getAttributeValueByName(scoping, "ProxyCount");
            return proxyCount.isEmpty() ? null : proxyCount;
        }
        return null;
    }

    /**
     * Extracts IDP entries from the IDPList within Scoping
     *
     * @return List of maps containing IDP information (ProviderID, Name), empty list if none found
     */
    public List<Map<String, String>> getIDPList() {
        List<Map<String, String>> idpList = new ArrayList<>();

        NodeList scopingNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "Scoping");
        if (scopingNodes.getLength() > 0) {
            Element scoping = (Element) scopingNodes.item(0);
            NodeList idpListNodes = scoping.getElementsByTagNameNS(SAML2P_NAMESPACE, "IDPList");

            if (idpListNodes.getLength() > 0) {
                Element idpListElement = (Element) idpListNodes.item(0);
                NodeList idpEntries = idpListElement.getElementsByTagNameNS(SAML2P_NAMESPACE, "IDPEntry");

                for (int i = 0; i < idpEntries.getLength(); i++) {
                    Element idpEntry = (Element) idpEntries.item(i);
                    Map<String, String> idpInfo = new HashMap<>();

                    String providerID = xmlHelpers.getAttributeValueByName(idpEntry, "ProviderID");
                    if (!providerID.isEmpty()) {
                        idpInfo.put("ProviderID", providerID);

                        String name = xmlHelpers.getAttributeValueByName(idpEntry, "Name");
                        if (!name.isEmpty()) {
                            idpInfo.put("Name", name);
                        } else {
                            idpInfo.put("Name", null);
                        }

                        idpList.add(idpInfo);
                    }
                }
            }
        }

        return idpList;
    }

    /**
     * Extracts RequesterID elements from Scoping
     *
     * @return List of RequesterID values, empty list if none found
     */
    public List<String> getRequesterIDs() {
        List<String> requesterIDs = new ArrayList<>();

        NodeList scopingNodes = root.getElementsByTagNameNS(SAML2P_NAMESPACE, "Scoping");
        if (scopingNodes.getLength() > 0) {
            Element scoping = (Element) scopingNodes.item(0);
            NodeList requesterIDNodes = scoping.getElementsByTagNameNS(SAML2P_NAMESPACE, "RequesterID");

            for (int i = 0; i < requesterIDNodes.getLength(); i++) {
                String requesterID = requesterIDNodes.item(i).getTextContent();
                if (requesterID != null && !requesterID.trim().isEmpty()) {
                    requesterIDs.add(requesterID.trim());
                }
            }
        }

        return requesterIDs;
    }

}