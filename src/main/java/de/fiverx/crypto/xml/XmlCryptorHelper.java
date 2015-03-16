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

import org.w3c.dom.Document;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Kurzer Satz der die Klasse beschreibt.
 * <p/>
 * Detailierte Beschreibung der Klasse
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler, knueppel
 * @since v1.0
 */
public interface XmlCryptorHelper {

    public void encrypt(Document document);

    public void decrypt(Document document);

    /**
     * added by Pascal Knueppel
     * @param document the document to encrypt
     * @param publicKey the necessary public key to encrypt the document
     */
    public void encrypt(Document document, PublicKey publicKey);

    /**
     * added by Pascal Knueppel
     * @param document the document to decrypt
     * @param privateKey the necessary private key to decrypt the document
     */
    public void decrypt(Document document, PrivateKey privateKey);

}
