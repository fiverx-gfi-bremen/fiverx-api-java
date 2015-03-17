package de.fiverx.crypto.xml;

import de.fiverx.crypto.ConfigHolder;
import de.fiverx.crypto.InternalCryptoException;
import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.*;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * author: Pascal Knueppel
 * created at: 16.03.2015.
 */



public class FiverxXmlSigning {
// comment:bz: Dieses Klasse ist teilweise durch kopieren einer "alten" Klasse entstanden. Wenn man die "alte" Klasse umbenennen und anpassen würde, bleibt die
// Commit-Historie erhalten. Im jetzigen Stand der API kann man evtl. auch auf Deprecations verzichten. Die API ist noch im Fluss, man muss eigentlich noch damit rechnen,
// dass auch größere, inkompatible Änderungen vorgenommen werden müssen.

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(FiverxXmlSigning.class);

    private String signatureIdAttribute = "sigId";

    // comment:bz:Die Klasse ist nicht "symetrisch" zu {{de.fiverx.crypto.xml.FiverxXmlCrypto}}, die einen {{KeyStoreHelper}} benötigt. So könnten alle Methoden hier auch statisch sein.
    public FiverxXmlSigning(){

    }

    /**
     * Creates a new document with an integrated signature. This technique is recommended because it is the most
     * uncomplicated way to use and to verify the signature.
     * @param doc the document that shall be signed
     * @param signingKey The private key the signature will be made with
     * @param signingCertificate the certificate that must be used to verify the signature
     * @return a copy of the original document
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     */
    public Document createEnvelopedSignature(Document doc, PrivateKey signingKey,
                                             X509Certificate signingCertificate) throws XMLSecurityException {
        Document document = XmlHelper.cloneDocument(doc);
        String signatureAlgorithm = ConfigHolder.XmlSigningHolder.getXmlSignatureAlgorithm();
        String canonicalizationMethod =  ConfigHolder.XmlSigningHolder.getXmlCanonicalzationMethod();

        // create xmlSignature with RSA-SHA1 Signature and canonizalization without comments
        XMLSignature xmlSignature = new XMLSignature( document,
                "",
                signatureAlgorithm,
                canonicalizationMethod);
        Element rootElement = document.getDocumentElement();
        // add signature to root element of document

        // The UUID is needed to reference the signature to the signed elements.
        String id = UUID.randomUUID().toString();
        rootElement.setAttributeNS(null, signatureIdAttribute, id);
        rootElement.setIdAttributeNS(null, signatureIdAttribute, true);
        Transforms transforms = new Transforms(document);
        transforms.addTransform(canonicalizationMethod);
        String messageDigestAlgorithm = ConfigHolder.XmlSigningHolder.getXmlDigestMethod();
        // generate the digest values and them to the document
        xmlSignature.addDocument("" , transforms, messageDigestAlgorithm, id, null);
        // sign the added digest values.
        xmlSignature.sign(signingKey);
        // append the signature to the document into the root-element.
        rootElement.appendChild(xmlSignature.getElement());
        // add the certificate to the signature so the signature can be verified. (does not provide real security of
        // course)
        xmlSignature.addKeyInfo(signingCertificate);
        return document;
    }

    /**
     * will verify an enveloped signature. Please make sure that the certificate inserted in the signature is
     * <p>trustworthy. You can extract the certificate with the method:
     * {@link #retrieveCertificateFromSignature(org.w3c.dom.Document)}</p>
     * @param document the document whose signature shall be verified
     * @return true if the signature fits to the given certificate in the signature (check the certificate first!),
     *         false else
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     */
    public boolean verifyEnvelopedSignature (Document document) throws XMLSecurityException {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Node sigElement = null;
        // find the signature element
        try {
            sigElement = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
//            e.printStackTrace();
            // comment:bz: e.printStacktrace sollte nie verwendet werden. Besser ist es, eine Bemerkung zu loggen, alternativ mit Stacktrace, z.B:
            if (LOG.isTraceEnabled()) {
                LOG.trace("verifyEnvelopedSignature: XPath-Fehler!", e);
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("verifyEnvelopedSignature: XPath-Fehler!" + e.getMessage());
            }
            // comment:bz: oder
            if (LOG.isDebugEnabled()) {
              LOG.debug("verifyEnvelopedSignature: kein Signatur-Element gefunden!");
            }
            // comment:bz: kann ich denn mit sigElement = null sinnvoll weitermachen?
        }
        // remove the signature element from the document
        document.getDocumentElement().removeChild(sigElement);
        expression = ".//ds:Reference[@Id][@URI]";
        NodeList referenceElements = null;
        // find the Reference nodes inside the signature element
        try {
            referenceElements = (NodeList) xpath.evaluate(expression, sigElement, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        }
        // iterate over any reference element and get the attribute with the UUID. This is normally the Id or the URI
        // attribute.
        // comment:bz: ein paar Leerzeilen machen den Code leserlicher, z.B:
        for (int x = 0; x < referenceElements.getLength(); x++) {
            Element referenceElement = (Element) referenceElements.item(x);
            String uuid = referenceElement.getAttribute("Id");

            if (uuid == null || uuid.trim().length() == 0) {
                uuid = referenceElement.getAttribute("URI");
            }

            if (uuid == null || uuid.trim().length() == 0) {
                throw new XMLSecurityException("No UUID Value was found in Reference Element");
            }

            // If the UUID was extraced successfully find all elements in the document that have an element with the
            // UUID as value.
            expression = ".//*[@*='" + uuid + "']";
            Node signedElement = null;

            try {
                signedElement = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
            } catch (XPathExpressionException e) {
                e.printStackTrace();
            }

            NamedNodeMap attributeMap = signedElement.getAttributes();
            // mark all elements with a fitting uuid that they are necessary for verifying the signature.

            for (int y = 0; y < attributeMap.getLength(); y++) {
                Node n = attributeMap.item(y);
                if (n.getNodeValue().equals(uuid)) {
                    ((Element)signedElement).setIdAttributeNS(null, n.getLocalName(), true);
                }
            }
        }
        // create the xmlSignature element
        // comment:bz wenn sigElement noch null ist (obige Exception wurde ja nur geloggt), dann wird hier eine XMLSecurityException geworfen, wenn ich das richtig gesehen habe.
        XMLSignature xmlSignature = new XMLSignature((Element) sigElement, "");
        // get the keyinfo so the certificate can be extracted
        KeyInfo ki = xmlSignature.getKeyInfo();
        if (ki == null) {
            // comment:bz: Wirf keine Exceptions aus Fremd-APIs weiter. Du bindest die Methoden-Signatur damit an Implementierungsdetails. Wenn man hier mal die Apache
            // Implementierung gegen etwas anderes austauschen möchte, dann ändert sich die Signatur inkompatibel.

            // comment:bz: Mein Vorschlag: Exceptions aus dem Crypto-Teil sind in der Regel fatal und verhindern eine weitere Ausführung. Ich würde vorschlagen (wie in den bisherigen
            // Klassen getan), dass alle Exceptions mit {{de.fiverx.crypto.InternalCryptoException}} oder Ableitungen davon gewrappt werden. Wenn man den Fehler tatsächlich sinnvoll
            // behandeln könnte, kann es eine spezialisierte Ableitung sein. Ansonsten sollte der Fehler zentral weiter oben verarbeitet werden, dann tut es die Basisklasse mit einer
            // passenden Message

            // throw new XMLSecurityException("Keine KeyInfo und damit kein Zertifikat in der Signatur enthalten!");
            throw new InternalCryptoException("Keine KeyInfo und damit kein Zertifikat in der Signatur enthalten!");
        }
        // The signature can be verfied because the sigElement does remember its parent document.
        return xmlSignature.checkSignatureValue(ki.getX509Certificate());
    }

    /**
     * Creates a new document that holds nothing but the signature. This technique is not recommended because the
     * signature and the document should not be parted.
     * @param document the document that shall be signed
     * @param signingKey The private key the signature will be made with
     * @param signingCertificate the certificate that must be used to verify the signature
     * @return a copy of the original document
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     *
     * @deprecated please use {@link #createEnvelopedSignature(org.w3c.dom.Document, java.security.PrivateKey, java.security.cert.X509Certificate)}
     */
    @Deprecated
    public Document createDetachedSignature (Document document, PrivateKey signingKey,
                                             X509Certificate signingCertificate) throws XMLSecurityException {
        String signatureAlgorithm = ConfigHolder.XmlSigningHolder.getXmlSignatureAlgorithm();
        String canonicalizationMethod =  ConfigHolder.XmlSigningHolder.getXmlCanonicalzationMethod();

        // create xmlSignature with RSA-SHA1 Signature and canonizalization without comments
        XMLSignature xmlSignature = new XMLSignature( document,
                "",
                signatureAlgorithm,
                canonicalizationMethod);
        Element rootElement = document.getDocumentElement();
        // add signature to root element of document

        // The UUID is needed to reference the signature to the signed elements.
        String id = UUID.randomUUID().toString();
        rootElement.setAttributeNS(null, signatureIdAttribute, id);
        rootElement.setIdAttributeNS(null, signatureIdAttribute, true);
        Transforms transforms = new Transforms(document);
        transforms.addTransform(canonicalizationMethod);
        String messageDigestAlgorithm = ConfigHolder.XmlSigningHolder.getXmlDigestMethod();
        // generate the digest values and them to the document
        xmlSignature.addDocument("" , transforms, messageDigestAlgorithm, id, null);
        // sign the added digest values.
        xmlSignature.sign(signingKey);
        // add the certificate to the signature so the signature can be verified. (does not provide real security of
        // course)
        xmlSignature.addKeyInfo(signingCertificate);
        try {
            return XmlHelper.retrieveXml(XmlHelper.elementToString(xmlSignature.getElement()));
        } catch (Exception e) {
            e.printStackTrace();
            throw new XMLSecurityException();
        }
    }

    /**
     * I was not able to implement a verification-method for a detached signature because Apache Santuario does not
     * support this technique directly.
     * @param document the document whose signature shall be verified
     * @param signatureDocument the document containing the signature
     * @return true if the signature fits to the given certificate in the signature (check the certificate first!),
     *         false else
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     *
     * @deprecated please use {@link #verifyEnvelopedSignature(org.w3c.dom.Document)}
     */
    @Deprecated
    public boolean verifyDetachedSignature (Document document, Document signatureDocument) throws XMLSecurityException {
        throw new XMLSecurityException("The verification of a detached signature is not supported");
    }

    /**
     * creates an enveloping signature. This technique is not recommended because verification of this signature type
     * is not directly supported in apache santuario
     * @param doc the document that shall be signed
     * @param signingKey the key to add the signature
     * @param signingCertificate the certificate needed to verify the signature
     * @return a Signature document containing the original document.
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     *
     * @deprecated please use {@link de.fiverx.crypto.xml.FiverxXmlSigning#createEnvelopedSignature(org.w3c.dom.Document, java.security.PrivateKey, java.security.cert.X509Certificate)}
     */
    @Deprecated
    public Document createEnvelopingSignature (Document doc, PrivateKey signingKey,
                                               X509Certificate signingCertificate) throws XMLSecurityException {
        Document document = XmlHelper.cloneDocument(doc);
        String signatureAlgorithm = ConfigHolder.XmlSigningHolder.getXmlSignatureAlgorithm();
        String canonicalizationMethod =  ConfigHolder.XmlSigningHolder.getXmlCanonicalzationMethod();

        // create xmlSignature with RSA-SHA1 Signature and canonizalization without comments
        XMLSignature xmlSignature = new XMLSignature( document,
                "",
                signatureAlgorithm,
                canonicalizationMethod);
        Element rootElement = document.getDocumentElement();
        // add signature to root element of document

        // The UUID is needed to reference the signature to the signed elements.
        String id = UUID.randomUUID().toString();
        rootElement.setAttributeNS(null, signatureIdAttribute, id);
        rootElement.setIdAttributeNS(null, signatureIdAttribute, true);
        Transforms transforms = new Transforms(document);
        transforms.addTransform(canonicalizationMethod);
        String messageDigestAlgorithm = ConfigHolder.XmlSigningHolder.getXmlDigestMethod();
        // generate the digest values and them to the document
        xmlSignature.addDocument("" , transforms, messageDigestAlgorithm, id, null);
        // sign the added digest values.
        xmlSignature.sign(signingKey);
        // append the signature to the document into the root-element.
        rootElement.appendChild(xmlSignature.getElement());
        // add the certificate to the signature so the signature can be verified. (does not provide real security of
        // course)
        xmlSignature.addKeyInfo(signingCertificate);
        xmlSignature.getDocument().getDocumentElement().appendChild(document.getDocumentElement());
        try {
            return XmlHelper.retrieveXml(XmlHelper.elementToString(xmlSignature.getElement()));
        } catch (Exception e) {
            e.printStackTrace();
            throw new XMLSecurityException();
        }
    }

    /**
     * I was not able to implement a verification-method for an enveloping signature because Apache Santuario does not
     * support this technique directly.
     * @param document the document whose signature shall be verified
     * @return true if the signature fits to the given certificate in the signature (check the certificate first!),
     *         false else
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     *
     * @deprecated please use {@link #verifyEnvelopedSignature(org.w3c.dom.Document)}
     */
    @Deprecated
    public boolean verifyEnvelopingSignature (Document document) throws XMLSecurityException {
        // comment:bz: keine unnötigen Informationen preis geben
        // throw new XMLSecurityException("Enveloping Signature wird von Apache Santuario nicht unterstützt");
        throw new XMLSecurityException("Enveloping Signature wird nicht unterstützt");
    }

    /**
     * Checks if the given document has a signature-element. This method is meaningful in this interface because it
     * is not understood that the signature is not always added the same way and that in different cases different
     * methods are needed to be implemented in order to find the signature element.
     * @param document the document that should contain a signature element
     * @return true if the signature is verified successfully, false else.
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     */
    public boolean containsSignature (Document document) {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element

        // comment:bz: duplicate code und hard coded Strings, z.B. mit {{retrieveCertificateFromSignature}}
        String expression = "//dsig:Signature[1]";
        Element sigElement;
        try {
            sigElement = (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return false;
        }
        return sigElement != null;
    }

    /**
     * Extracts the certificate burried in the signature element. Use it to verify that this certificate is
     * trustworthy and check the signature afterwards
     * @param document The document that holds a signature element.
     * @return The certificate held by the signature element.
     * @throws org.apache.xml.security.exceptions.XMLSecurityException
     */
    public X509Certificate retrieveCertificateFromSignature (Document document) throws XMLSecurityException {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Element sigElement;
        try {
            sigElement = (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return null;
        }
        XMLSignature xmlSignature = new XMLSignature(sigElement, "");
        KeyInfo ki = xmlSignature.getKeyInfo();
        return ki.getX509Certificate();
    }
}
