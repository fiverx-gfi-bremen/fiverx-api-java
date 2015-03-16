package de.fiverx.crypto.xml;

import de.fiverx.crypto.ConfigHolder;
import de.fiverx.crypto.keystore.FilebasedKeyStorePersistenceHandler;
import de.fiverx.crypto.keystore.KeyStoreHelper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.*;

import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * user: pknueppe
 * created at: 16.03.2015.
 *
 * this testclass was made to develop the method verifyComplexSignature in the class
 * de.fiverx.crypto.xml.XmlSigningHelperRsaSha1
 */
public class XPathTester {

    private Document document;
    private KeyStore dotNetClientKeyStore;
    private String clientAlias = "testclient";
    private char[] clientPassword = "testc".toCharArray();
    private X509Certificate verficationCertificate;

    @Before
    public void init( ) throws Exception {
        org.apache.xml.security.Init.init();
        String xml = "<Request><data>Dies ist eine Testanfrage</data></Request>";
        Security.addProvider(new BouncyCastleProvider());

        dotNetClientKeyStore = KeyStore.getInstance("PKCS12");
        dotNetClientKeyStore.load(getClass().getResourceAsStream("/testKeys/TestDotNetClientZertifikat.pfx"),
                                                                 "testc".toCharArray());

        document = XmlHelper.retrieveXml(xml);
        XmlSigningHelper xmlSigning = new XmlSigningHelperRsaSha1();
        xmlSigning.addSignatureToDocument(document,
                (PrivateKey) dotNetClientKeyStore.getKey(clientAlias, clientPassword),
                (X509Certificate) dotNetClientKeyStore.getCertificate(clientAlias));
        verficationCertificate = (X509Certificate) dotNetClientKeyStore.getCertificate(clientAlias);
    }

    @Test
    public void encrypt () throws TransformerException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        XmlCryptorHelper xmlCrypto = new XmlCryptoHelperRsaOaepAes256();
        xmlCrypto.encrypt(document, dotNetClientKeyStore.getCertificate(clientAlias).getPublicKey());
        System.err.println(XmlHelper.documentToString(document));
        System.err.println("********************************");
        xmlCrypto.decrypt(document, (PrivateKey) dotNetClientKeyStore.getKey(clientAlias, clientPassword));
        System.err.println(XmlHelper.documentToString(document));
    }

//    @Test
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
//                    document.getDocumentElement().setIdAttributeNS(null, n.getLocalName(), true);
                    ((Element)signedElement).setIdAttributeNS(null, n.getLocalName(), true);
                }
            }
        }
        XMLSignature xmlSignature = new XMLSignature((Element) sigElement, "");

        KeyInfo ki = xmlSignature.getKeyInfo();
        if (ki == null) {
            throw new XMLSecurityException("Keine KeyInfo und damit kein Zertifikat in der Signatur enthalten!");
        }
        Assert.assertTrue(xmlSignature.checkSignatureValue(verficationCertificate));
    }
}
