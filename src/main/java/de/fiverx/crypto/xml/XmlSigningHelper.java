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

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Author: Pascal Knueppel
 * Date: 18.02.2015
 * Time: 17:21
 *
 * marked deprecated by Pascal Knueppel
 * @deprecated replaced by
 *      {@link de.fiverx.crypto.xml.FiverxXmlSigning}
 */
@Deprecated
public interface XmlSigningHelper {

    /**
     * To add a signature to a document
     * @param document the document that shall get a signature
     * @param signingKey the key to sign the document
     * @param signingCertificate the certificate that will be added to the signature, so the receiver of this message
     *                           knows who sent it by recognizing the certificate.
     * @throws XMLSecurityException
     */
    public void addSignatureToDocument (Document document, PrivateKey signingKey, X509Certificate signingCertificate)
            throws XMLSecurityException;

    /**
     * To verify the signature of a document
     * Please always confirm if the given certificate in the signature is trustworthy or not before verifying the
     * signature
     * @param document the document from which the signature shall be verified.
     * @param verficationCertificate the certificate that is used to verify the signature.
     * @return true if the signature was verified successfully, false else.
     * @throws XMLSecurityException
     */
    public boolean verifySignature (Document document, X509Certificate verficationCertificate)
            throws XMLSecurityException;

    /**
     * Checks if the given document has a signature-element. This method is meaningful in this interface because it
     * is not understood that the signature is not always added the same way and that in different cases different
     * methods are needed to be implemented in order to find the signature element.
     * @param document the document that should contain a signature element
     * @return true if the signature is verified successfully, false else.
     * @throws XMLSecurityException
     */
    public boolean doesContainSignature (Document document) throws XMLSecurityException;

    /**
     * Extracts the certificate burried in the signature element. Use it to verify that this certificate is
     * trustworthy and check the signature afterwards
     * @param document The document that holds a signature element.
     * @return The certificate held by the signature element.
     * @throws XMLSecurityException
     */
    public X509Certificate retrieveCertificateFromSignature (Document document) throws XMLSecurityException;
}
