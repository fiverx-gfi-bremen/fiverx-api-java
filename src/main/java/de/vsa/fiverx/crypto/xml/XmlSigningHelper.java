package de.vsa.fiverx.crypto.xml;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Author: Pascal Knueppel
 * Date: 18.02.2015
 * Time: 17:21
 */
public interface XmlSigningHelper {

    public void addSignatureToDocument (Document document, PrivateKey signingKey, X509Certificate signingCertificate)
            throws XMLSecurityException;

    public boolean verifySignature (Document document, X509Certificate verficationCertificate)
            throws XMLSecurityException;
}
