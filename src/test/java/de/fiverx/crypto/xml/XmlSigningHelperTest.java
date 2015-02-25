package de.fiverx.crypto.xml;

import de.fiverx.crypto.keystore.KeyStoreHelper;
import de.fiverx.crypto.keystore.KeyStorePersistenceHandler;
import de.fiverx.crypto.keystore.ResourceKeyStorePersistenceHandler;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;

/**
 * user: pknueppe
 * created at: 19.02.2015.
 */
public class XmlSigningHelperTest {

    private KeyStoreHelper caKeyStoreHelper;
    private KeyStoreHelper apoKeyStoreHelper;
    private Document plainDocument;

    @Before
    public void init() throws Exception {
        KeyStorePersistenceHandler clientKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler
                ("crypto/client/client-store.jceks", "clientpw");
        apoKeyStoreHelper = new KeyStoreHelper(clientKeyStorePersistenceHandler, "clientpw",
                "theapo", "root");

        KeyStorePersistenceHandler caKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler
                ("crypto/ca/ca-store.jceks", "itsokitsok");
        caKeyStoreHelper = new KeyStoreHelper(caKeyStorePersistenceHandler, "itsokitsok",
                "vsaca", "root");

        plainDocument = XmlHelper.retrieveXml(new File("src/test/resources/data/purchase.xml"));
    }

    @Test
    public void addSignatureToDocumentTest() throws XMLSecurityException, XPathExpressionException {
        XmlSigningHelper xmlSigningHelper = new XmlSigningHelperRsaSha1();
        Document copyOfPlainDocument = (Document) plainDocument.cloneNode(true);
        // CA signs the document
        xmlSigningHelper.addSignatureToDocument(copyOfPlainDocument,
                                                caKeyStoreHelper.getMyPrivateKey(),
                                                caKeyStoreHelper.getMyX509Certificate());
        // Now verify that the signature was indeed added into the document
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Element sigElement;
        sigElement = (Element) xpath.evaluate(expression, copyOfPlainDocument, XPathConstants.NODE);
        Assert.assertNotNull("Signature element was not found inside the document", sigElement);
    }

    @Test
    public void verifySignatureTest() throws XMLSecurityException {
        XmlSigningHelper xmlSigningHelper = new XmlSigningHelperRsaSha1();
        Document copyOfPlainDocument = (Document) plainDocument.cloneNode(true);
        // CA signs the document
        xmlSigningHelper.addSignatureToDocument(copyOfPlainDocument,
                                                caKeyStoreHelper.getMyPrivateKey(),
                                                caKeyStoreHelper.getMyX509Certificate());
        // Assuming the client is in possession of the certificate of the CA. The document will be given to this
        // function along with the certificate of the CA to verify the signature the CA made.
        Assert.assertTrue(
            xmlSigningHelper.verifySignature(copyOfPlainDocument, caKeyStoreHelper.getMyX509Certificate()));
    }
}
