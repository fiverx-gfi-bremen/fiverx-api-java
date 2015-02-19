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

package de.vsa.fiverx.crypto;

import de.vsa.fiverx.crypto.xml.CryptoHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
public class TestClientSideStoreConsistency {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(TestClientSideStoreConsistency.class);

    @Test
    public void testClientStore() throws Exception {
        CryptoHelper clientCryptoHelper = CryptoHelper.clientCryptoHelper();

        // Retrieve root certificate of our CA
        Certificate rootCertificate = clientCryptoHelper.getOtherCertificate();
        assertNotNull(rootCertificate);
        // Retrieve user certificate
        Certificate clientCertificate = clientCryptoHelper.getMyCertificate();
        assertNotNull(clientCertificate);
        // Retrieve public key of the root certificate
        PublicKey serverPublicKey = clientCryptoHelper.getOtherPublicKey();
        assertNotNull(serverPublicKey);
        if (LOG.isInfoEnabled()) {
          LOG.info("testClientStore: serverPublicKey=" + Base64.encodeBase64String(serverPublicKey.getEncoded()));
        }
        // Retrieve public key of the user certificate
        PublicKey clientPublicKey = clientCryptoHelper.getMyPublicKey();
        assertNotNull(clientPublicKey);
        if (LOG.isInfoEnabled()) {
            LOG.info("testClientStore: clientPublicKey=" + Base64.encodeBase64String(clientPublicKey.getEncoded()));
        }
        // retrieve private key of the user
        PrivateKey clientPrivateKey = clientCryptoHelper.getMyPrivateKey();
        assertNotNull(clientPrivateKey);
        if (LOG.isInfoEnabled()) {
            LOG.info("testClientStore: clientPrivateKey=" + Base64.encodeBase64String(clientPrivateKey.getEncoded()));
        }
        // check certification chain, which consists of two entries (user certificate and root certificate of our CA)
        Certificate[] certificateChain = clientCryptoHelper.getKeyStore().getCertificateChain("theapo");
        assertNotNull(certificateChain);
        assertEquals(2, certificateChain.length);
    }
}
