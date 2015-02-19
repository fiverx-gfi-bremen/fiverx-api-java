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

package de.vsa.fiverx.crypto.xml;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
 */
public class XmlSigningHelperRsaSha1 implements XmlSigningHelper{

    static {
        org.apache.xml.security.Init.init();
    }

    @Override
    public void addSignatureToDocument (Document document, PrivateKey signingKey, X509Certificate signingCertificate)
            throws XMLSecurityException {
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
        rootElement.setAttributeNS(null, "sigId", id);
        rootElement.setIdAttributeNS(null, "sigId", true);
        Transforms transforms = new Transforms(document);
        transforms.addTransform(canonicalizationMethod);
        String messageDigestAlgorithm = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
        // generate the digest values and them to the document
        xmlSignature.addDocument("#" + id , transforms, messageDigestAlgorithm);
        // sign the added digest values.
        xmlSignature.sign(signingKey);
        // append the signature to the document into the root-element.
        rootElement.appendChild(xmlSignature.getElement());
        // add the certificate to the signature so the signature can be verified. (does not provide real security of
        // course)
        xmlSignature.addKeyInfo(signingCertificate);
    }

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
}
