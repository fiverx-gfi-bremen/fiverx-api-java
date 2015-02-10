/*
 * Copyright (c) 2015 VSA Gmbh
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

package de.vsa.fiverx.poc.xml;

import de.vsa.fiverx.poc.keystore.KeyStoreHelper;
import de.vsa.fiverx.poc.keystore.KeyStorePersistenceHandler;
import de.vsa.fiverx.poc.keystore.ResourceKeyStorePersistenceHandler;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import java.io.File;

import static org.junit.Assert.assertTrue;

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
public class TestXmlCrypto {

    private File sourceXmlFile = new File("src/test/resources/data/purchase.xml");

    private File encryptedXmlFile = new File("build/tmp/encrypted.xml");

    private File decryptedXmlFile = new File("build/tmp/decrypted.xml");

    @Before
    public void setUp() {
        if (encryptedXmlFile.exists()) {
            assertTrue(encryptedXmlFile.delete());
        }
        if (decryptedXmlFile.exists()) {
            assertTrue(decryptedXmlFile.delete());
        }
        encryptedXmlFile.getParentFile().mkdirs();
    }

    @Test
    public void testXmlEncryptionDecryptionClientToServer() throws Exception {
        // client side initialisation
        KeyStorePersistenceHandler clientKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler("crypto/client/client-store.jceks", "clientpw");
        KeyStoreHelper clientKeyStoreHelper = new KeyStoreHelper(clientKeyStorePersistenceHandler, "clientpw", "theapo", "root");
        XmlCryptorHelper clientXmlCryptoHelper = new XmlCryptoHelperRsaOaepAes256(clientKeyStoreHelper);

        // read the testfile from the filesystem as DOM
        Document xml = XmlHelper.retrieveXml(sourceXmlFile);
        // encrypt
        clientXmlCryptoHelper.encrypt(xml);
        // write xml file
        XmlHelper.writeDocToFile(xml, encryptedXmlFile, false);


        // serverside initialisation
        KeyStorePersistenceHandler serverKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler("crypto/ca/ca-store.jceks", "itsokitsok");
        KeyStoreHelper serverKeyStoreHelper = new KeyStoreHelper(serverKeyStorePersistenceHandler, "itsokitsok", "vsaca", "theapo");
        XmlCryptorHelper serverXmlCryptoHelper = new XmlCryptoHelperRsaOaepAes256(serverKeyStoreHelper);

        // read the encrypted XML from file system as DOM from file system (it's a new instance!)
        xml = XmlHelper.retrieveXml(encryptedXmlFile);
        serverXmlCryptoHelper.decrypt(xml);
        // and write the decrypted XML to disk
        XmlHelper.writeDocToFile(xml, decryptedXmlFile, true);

        TestXmlHelper.checkBookingEncoding(decryptedXmlFile);
    }

}
