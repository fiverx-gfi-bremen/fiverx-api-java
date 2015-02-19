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
