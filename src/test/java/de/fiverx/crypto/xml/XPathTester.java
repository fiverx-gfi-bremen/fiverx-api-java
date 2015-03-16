package de.fiverx.crypto.xml;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.*;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

/**
 * user: pknueppe
 * created at: 16.03.2015.
 *
 * this testclass was made to develop the method verifyComplexSignature in the class
 * de.fiverx.crypto.xml.XmlSigningHelperRsaSha1
 */
public class XPathTester {

    private Document document;

    @Before
    public void init( ) throws Exception {
        org.apache.xml.security.Init.init();
        String xml = "<Request><data>Dies ist eine Testanfrage</data></Request>";
        document = XmlHelper.retrieveXml(xml);
    }

    @Test
    public void testXPath () throws Exception {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Node sigElement = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
        Assert.assertNotNull(sigElement);
        document.getDocumentElement().removeChild(sigElement);
        expression = ".//ds:Reference[@Id][@URI]";
        NodeList referenceElements = (NodeList) xpath.evaluate(expression, sigElement, XPathConstants.NODESET);
        for (int x = 0; x < referenceElements.getLength(); x++) {
            Element referenceElement = (Element) referenceElements.item(x);
            String uuid = referenceElement.getAttribute("Id");
            if (uuid == null || uuid.trim().length() == 0) {
                uuid = referenceElement.getAttribute("URI");
            }
            if (uuid == null || uuid.trim().length() == 0) {
                throw new Exception("No UUID Value was found in Reference Element");
            }
            expression = ".//*[@*='" + uuid + "']";
            Node signedElement = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
            Assert.assertNotNull(signedElement);
            NamedNodeMap attributeMap = signedElement.getAttributes();
            for (int y = 0; y < attributeMap.getLength(); y++) {
                Node n = attributeMap.item(y);
                if (n.getNodeValue().equals(uuid)) {
                    System.out.println(n.getLocalName());
                    ((Element)signedElement).setIdAttributeNS(null, n.getLocalName(), true);
                }
            }
        }
    }
}
