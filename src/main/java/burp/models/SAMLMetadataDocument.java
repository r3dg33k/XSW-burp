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

import static burp.utilities.helpers.Constants.SAML2_METADATA_NAMESPACE;
import static burp.utilities.helpers.Constants.UNDEFINED_ATTRNAME_FORMAT;

public class SAMLMetadataDocument {

    private final Document document;
    private final Element root;
    private final XMLHelpers xmlHelpers;

    public SAMLMetadataDocument(Document document) {
        this.document = document;
        this.root = document.getDocumentElement();
        this.xmlHelpers = XMLHelpers.getInstance();
    }

    public Document getDocument() {
        return document;
    }

    public Node getFirstChild() {
        return root;
    }

    /**
     * Extracts the ID from the metadata
     *
     * @return ID or null if not found
     */
    public String getID() {
        String id = xmlHelpers.getAttributeValueByName(root, "ID");
        return id.isEmpty() ? null : id;
    }

    /**
     * Extracts the EntityID from the metadata
     *
     * @return EntityID or null if not found
     */
    public String getEntityID() {
        String entityID = xmlHelpers.getAttributeValueByName(root, "entityID");
        return entityID.isEmpty() ? null : entityID;
    }

    /**
     * Checks if the metadata contains an IDPSSODescriptor
     *
     * @return true if IDPSSODescriptor exists
     */
    public boolean hasIDPSSODescriptor() {
        NodeList descriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "IDPSSODescriptor");
        return descriptors.getLength() > 0;
    }

    /**
     * Checks if the metadata contains an SPSSODescriptor
     *
     * @return true if SPSSODescriptor exists
     */
    public boolean hasSPSSODescriptor() {
        NodeList descriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SPSSODescriptor");
        return descriptors.getLength() > 0;
    }

    /**
     * Extracts an X509 certificate from the metadata as base64 string
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
     * Checks if the metadata is signed
     *
     * @return true if Signature element exists
     */
    public boolean isSigned() {
        return getSignature() != null;
    }

    /**
     * Extracts Single Sign-On service endpoints from IDPSSODescriptor
     *
     * @return Map of binding to location, empty map if none found
     */
    public Map<String, String> getIDPSSOServiceEndpoints() {
        Map<String, String> endpoints = new HashMap<>();

        NodeList descriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "IDPSSODescriptor");
        if (descriptors.getLength() == 0) {
            return endpoints;
        }

        Element idpDescriptor = (Element) descriptors.item(0);
        NodeList ssoServices = idpDescriptor.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SingleSignOnService");

        for (int i = 0; i < ssoServices.getLength(); i++) {
            Element ssoService = (Element) ssoServices.item(i);
            String binding = ssoService.getAttribute("Binding");
            String location = ssoService.getAttribute("Location");

            if (!binding.isEmpty() && !location.isEmpty()) {
                endpoints.put(binding, location);
            }
        }

        return endpoints;
    }

    /**
     * Extracts Assertion Consumer Service endpoints from SPSSODescriptor
     *
     * @return Map of binding to location, empty map if none found
     */
    public Map<String, String> getSPAssertionConsumerServiceEndpoints() {
        Map<String, String> endpoints = new HashMap<>();

        NodeList descriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SPSSODescriptor");
        if (descriptors.getLength() == 0) {
            return endpoints;
        }

        Element spDescriptor = (Element) descriptors.item(0);
        NodeList acsServices = spDescriptor.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "AssertionConsumerService");

        for (int i = 0; i < acsServices.getLength(); i++) {
            Element acsService = (Element) acsServices.item(i);
            String binding = acsService.getAttribute("Binding");
            String location = acsService.getAttribute("Location");

            if (!binding.isEmpty() && !location.isEmpty()) {
                endpoints.put(binding, location);
            }
        }

        return endpoints;
    }

    /**
     * Gets the organization display name
     *
     * @return Organization display name or null if not found
     */
    public String getOrganizationDisplayName() {
        NodeList organizations = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "Organization");
        if (organizations.getLength() == 0) {
            return null;
        }

        Element organization = (Element) organizations.item(0);
        NodeList displayNames = organization.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "OrganizationDisplayName");

        if (displayNames.getLength() > 0) {
            return displayNames.item(0).getTextContent();
        }

        return null;
    }

    /**
     * Gets the validity period of the metadata
     *
     * @return Map containing "validUntil" and "cacheDuration" if present, empty map otherwise
     */
    public Map<String, String> getValidityInfo() {
        Map<String, String> validity = new HashMap<>();

        String validUntil = root.getAttribute("validUntil");
        if (!validUntil.isEmpty()) {
            validity.put("validUntil", validUntil);
        }

        String cacheDuration = root.getAttribute("cacheDuration");
        if (!cacheDuration.isEmpty()) {
            validity.put("cacheDuration", cacheDuration);
        }

        return validity;
    }

    /**
     * Gets NameID formats supported
     *
     * @return List of NameID format URIs, empty list if none found
     */
    public List<String> getNameIDFormats() {
        List<String> formats = new ArrayList<>();

        NodeList nameIDFormatNodes = document.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "NameIDFormat");
        for (int i = 0; i < nameIDFormatNodes.getLength(); i++) {
            String format = nameIDFormatNodes.item(i).getTextContent();
            if (format != null && !format.trim().isEmpty()) {
                formats.add(format.trim());
            }
        }

        return formats;
    }

    /**
     * Gets Single Logout service endpoints
     *
     * @return Map of binding to location, empty map if none found
     */
    public Map<String, String> getSingleLogoutServiceEndpoints() {
        Map<String, String> endpoints = new HashMap<>();

        NodeList sloServices = document.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SingleLogoutService");
        for (int i = 0; i < sloServices.getLength(); i++) {
            Element sloService = (Element) sloServices.item(i);
            String binding = sloService.getAttribute("Binding");
            String location = sloService.getAttribute("Location");

            if (!binding.isEmpty() && !location.isEmpty()) {
                endpoints.put(binding, location);
            }
        }

        return endpoints;
    }

    /**
     * Extracts requested attributes from AttributeConsumingService in SPSSODescriptor
     *
     * @return Map of attribute name to NameFormat, empty map if none found
     */
    public Map<String, String> getRequestedAttributes() {
        Map<String, String> attributes = new HashMap<>();

        NodeList spDescriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SPSSODescriptor");
        if (spDescriptors.getLength() == 0) {
            return attributes;
        }

        for (int i = 0; i < spDescriptors.getLength(); i++) {
            Element spDescriptor = (Element) spDescriptors.item(i);
            NodeList attributeConsumingServices = spDescriptor.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "AttributeConsumingService");

            for (int j = 0; j < attributeConsumingServices.getLength(); j++) {
                Element attributeConsumingService = (Element) attributeConsumingServices.item(j);
                NodeList requestedAttributes = attributeConsumingService.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "RequestedAttribute");

                for (int k = 0; k < requestedAttributes.getLength(); k++) {
                    Element requestedAttribute = (Element) requestedAttributes.item(k);
                    String attributeName = requestedAttribute.getAttribute("Name");

                    if (!attributeName.trim().isEmpty()) {
                        String nameFormat = requestedAttribute.getAttribute("NameFormat");
                        String actualNameFormat;

                        if (!nameFormat.trim().isEmpty()) {
                            actualNameFormat = nameFormat.trim();
                        } else {
                            actualNameFormat = UNDEFINED_ATTRNAME_FORMAT;
                        }

                        attributes.put(attributeName, actualNameFormat);
                    }
                }
            }
        }

        return attributes;
    }

    /**
     * Extracts requested attributes from AttributeConsumingService in IDPSSODescriptor
     *
     * @return Map of attribute name to NameFormat, empty map if none found
     */
    public Map<String, String> getIDPAttributes() {
        Map<String, String> attributes = new HashMap<>();

        NodeList spDescriptors = root.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "SPSSODescriptor");
        if (spDescriptors.getLength() == 0) {
            return attributes;
        }

        for (int i = 0; i < spDescriptors.getLength(); i++) {
            Element spDescriptor = (Element) spDescriptors.item(i);
            NodeList attributeConsumingServices = spDescriptor.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "AttributeConsumingService");

            for (int j = 0; j < attributeConsumingServices.getLength(); j++) {
                Element attributeConsumingService = (Element) attributeConsumingServices.item(j);
                NodeList requestedAttributes = attributeConsumingService.getElementsByTagNameNS(SAML2_METADATA_NAMESPACE, "RequestedAttribute");

                for (int k = 0; k < requestedAttributes.getLength(); k++) {
                    Element requestedAttribute = (Element) requestedAttributes.item(k);
                    String attributeName = requestedAttribute.getAttribute("Name");

                    if (!attributeName.trim().isEmpty()) {
                        String nameFormat = requestedAttribute.getAttribute("NameFormat");
                        String actualNameFormat;

                        if (!nameFormat.trim().isEmpty()) {
                            actualNameFormat = nameFormat.trim();
                        } else {
                            actualNameFormat = UNDEFINED_ATTRNAME_FORMAT;
                        }

                        attributes.put(attributeName, actualNameFormat);
                    }
                }
            }
        }

        return attributes;
    }
}