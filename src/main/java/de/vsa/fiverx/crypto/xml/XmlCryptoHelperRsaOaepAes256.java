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

import de.vsa.fiverx.crypto.InternalCryptoException;
import de.vsa.fiverx.crypto.keystore.KeyStoreHelper;
import de.vsa.fiverx.crypto.plain.crypto.AesCryptoHelper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Kurzer Satz der die Klasse beschreibt.
 * <p/>
 * Detailierte Beschreibung der Klasse
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 */
public class XmlCryptoHelperRsaOaepAes256 implements XmlCryptorHelper {

    static {
        org.apache.xml.security.Init.init();
    }

    private KeyStoreHelper keyStoreHelper;

    public XmlCryptoHelperRsaOaepAes256(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }

    public void encrypt(Document document) {
        try {
            // generate a secret key as session key for data encryption (AES/CBC/PKCS7Padding)
            SecretKey dataKey = AesCryptoHelper.getAesCbcPkcs7PaddingInstance().getSecretKeyInstance(); // this is a one time usage key; change to a session key if wanted...
            // retrieve the partners public RSA key for asymetric key encryption
            PublicKey kek = keyStoreHelper.getOtherPublicKey();
            // create a cipher instance
            XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
            // switch to wrap mode since we want to encrypt a key
            keyCipher.init(XMLCipher.WRAP_MODE, kek);
            // key encryption
            EncryptedKey encryptedKey = keyCipher.encryptKey(document, dataKey);
            // encrypt the XML (we will encrypt all for now, therefore the root element)
            Element rootElement = document.getDocumentElement();
            // create a new cipher for symetric data encryption
            XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_256);
            // initalize cipher for encryption with the  generated key
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
            // encrypted data
            EncryptedData encryptedData = xmlCipher.getEncryptedData();
            // create the key info (used algorithm, ...)
            KeyInfo keyInfo = new KeyInfo(document);
            // add the session key
            keyInfo.add(encryptedKey);
            // add a key name; looks like .NET seems to need one even when could be defaulted to the only one available
            keyInfo.addKeyName("rsaKeyName"); // the keyname should be the api identity, e.g. the ik
            // set the key info
            encryptedData.setKeyInfo(keyInfo);
            // finally, do the encryption job
            xmlCipher.doFinal(document, rootElement, true);
        } catch (Exception e) { // unfortunately, doFinal only throws Exception...
            throw new InternalCryptoException(e);
        }
    }

    public void decrypt(Document document) {
        try {
            // retrieve my private RSA key
            PrivateKey caKek = keyStoreHelper.getMyPrivateKey();
            // enryption should be done for the first element (root element)
            Element encryptedDataElement = (Element) document.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
            // create a new cipher instance (no further information, the cipher will know what to do)
            XMLCipher xmlCipher = XMLCipher.getInstance();
            // initialize the cipher for decryption; no key is provided, since the encrypted XML contains the key and everything else
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            // set the key for key decryption
            xmlCipher.setKEK(caKek);
            // finally, do the decryption job
            xmlCipher.doFinal(document, encryptedDataElement);
        } catch (Exception e) {
            throw new InternalCryptoException(e);
        }
    }

}
