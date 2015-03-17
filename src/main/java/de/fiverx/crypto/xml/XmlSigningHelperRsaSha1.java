/*
 * Copyright (c) 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.fiverx.crypto.xml;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
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
 * Author: Pascal Knueppel
 * Date: 18.02.2015
 * Time: 17:24
 *
 * This class is meant to add Signatures to documents and verify them
 *
 * @deprecated replaced by
 *      {@link de.fiverx.crypto.xml.FiverxXmlSigning}
 */
@Deprecated
public class XmlSigningHelperRsaSha1 implements XmlSigningHelper{

    /**
     * Initialize Apache.Santuario for XML-Security operations
     */
    static {
        org.apache.xml.security.Init.init();
    }

    /** This Attribute shall mark the elements that are to be signed */
    private static final String signatureIdAttribute = "sigId";

    /**
     * Create a Signature and add it to the document.
     * @param document The XML-Socument that shall be signed
     * @param signingKey The private key that is needed to create the signature
     * @param signingCertificate the certificate that should be added to the signature so the receiver knows who has
     *                           sent this message
     * @throws XMLSecurityException
     */
    @Override
    public void addSignatureToDocument (Document document, PrivateKey signingKey, X509Certificate signingCertificate)
            throws XMLSecurityException {
        createEnvelopedSignature(document, signingKey, signingCertificate);
    }

    /**
     * This method takes a Document and adds a Signature into the root-Element. the result will be an
     * enveloped-Signature
     * @param document The XML-Socument that shall be signed
     * @param signingKey The private key that is needed to create the signature
     * @param signingCertificate the certificate that should be added to the signature so the receiver knows who has
     *                           sent this message
     * @throws XMLSecurityException
     */
    public void createEnvelopedSignature (Document document, PrivateKey signingKey, X509Certificate signingCertificate)
            throws XMLSecurityException{
        String signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
        String canonicalizationMethod = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

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
        String messageDigestAlgorithm = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
        // generate the digest values and them to the document
        xmlSignature.addDocument("" , transforms, messageDigestAlgorithm, id, null);
        // sign the added digest values.
        xmlSignature.sign(signingKey);
        // append the signature to the document into the root-element.
        rootElement.appendChild(xmlSignature.getElement());
        // add the certificate to the signature so the signature can be verified. (does not provide real security of
        // course)
        xmlSignature.addKeyInfo(signingCertificate);
    }

    /**
     * Verifies a simple signature. This method expects that the signature was build over the whole document and that
     * the root-Element of the XML-Document is the reference of the signature.
     * Also this method expects the signature to be an enveloped-signature.
     * @param document The document that contains the signature.
     * @param verficationCertificate The Certificate that is needed to verify the Signature.
     *                               It is actually possible to read the Certificate from the Signature but before
     *                               verifying ths signature the receiver should be sure, that this certificate is
     *                               trusted.
     * @return true if signature corresponds to the given certificate, false else.
     * @throws XMLSecurityException
     */
    @Override
    public boolean verifySignature (Document document, X509Certificate verficationCertificate)
            throws XMLSecurityException {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Element sigElement;
        try {
            sigElement = (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return false;
        }
        assert sigElement != null;

        Element rootElement = document.getDocumentElement();
        // it is necessary to register the sigId-Attribute if the document is moved over system boundaries like from
        // a client to a server. Otherwise the reference-number cannot be validated.
        rootElement.setIdAttributeNS(null, signatureIdAttribute, true);
        // do not build the hash over the signature element. Therefore remove it from the document.
        rootElement.removeChild(sigElement);

        XMLSignature xmlSignature = new XMLSignature(sigElement, "");

        KeyInfo ki = xmlSignature.getKeyInfo();
        if (ki == null) {
            throw new XMLSecurityException("Keine KeyInfo und damit kein Zertifikat in der Signatur enthalten!");
        }
        // Check the Signature value
        return xmlSignature.checkSignatureValue(verficationCertificate);
    }

    /**
     * This method is for verifying complex signatures that have been made over several elements of the document and
     * not on the root-Element itself. Also This method will take no account to the variable signatureIdAttribute.
     * This circumstance leads to the advantage that this method does not need to know anything about the signature
     * in advance. It will build all necessary data itself and verifies the signature in the end. The rsulting
     * disadvantage is that this method might slow down the application a little bit. It depends highly on XPath.
     *
     * This method expects a Document with an enveloped Signature.
     *
     * @param document The document of whicht the Signature shall be verified.
     * @param verficationCertificate the certificate that should be used to verify the signautre.
     * @return true if signature corresponds to the given certificate, false else.
     * @throws Exception
     */
    public boolean verifyComplexSignature (Document document, X509Certificate verficationCertificate) throws Exception {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
        String expression = "//dsig:Signature[1]";
        Node sigElement = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
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
            NamedNodeMap attributeMap = signedElement.getAttributes();
            for (int y = 0; y < attributeMap.getLength(); y++) {
                Node n = attributeMap.item(y);
                if (n.getNodeValue().equals(uuid)) {
                    // comment:bz: System.out, System.err und printStackTrace durch Logging ersetzen
                    System.out.println(n.getLocalName());
                    ((Element)signedElement).setIdAttributeNS(null, n.getLocalName(), true);
                }
            }
        }
        XMLSignature xmlSignature = new XMLSignature((Element) sigElement, "");

        KeyInfo ki = xmlSignature.getKeyInfo();
        if (ki == null) {
            throw new XMLSecurityException("Keine KeyInfo und damit kein Zertifikat in der Signatur enthalten!");
        }
        return xmlSignature.checkSignatureValue(verficationCertificate);
    }

    /**
     * Checks if the given document has a signature-element. This method is meaningful in this interface because it
     * is not understood that the signature is not always added the same way and that in different cases different
     * methods are needed to be implemented in order to find the signature element.
     * @param document the document that should contain a signature element
     * @return true if the signature is verified successfully, false else.
     * @throws XMLSecurityException
     */
    @Override
    public boolean doesContainSignature (Document document) {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        // Find the Signature Element
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
     * @throws XMLSecurityException
     */
    @Override
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
