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

package de.vsa.fiverx.poc;

import de.vsa.fiverx.poc.xml.CryptoHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

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
public class TestServerSideStoreConsistency {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(TestServerSideStoreConsistency.class);

    @Test
    public void testServerStore() throws Exception {
        CryptoHelper serverCryptoHelper = CryptoHelper.serverCryptoHelper();

        Certificate serverCertificate = serverCryptoHelper.getMyCertificate();
        assertNotNull(serverCertificate);
        PublicKey serverPublicKey = serverCryptoHelper.getMyPublicKey();
        assertNotNull(serverPublicKey);
        if (LOG.isInfoEnabled()) {
            LOG.info("testServerStore: serverPublicKey=" + Base64.encodeBase64String(serverPublicKey.getEncoded()));
        }
        Certificate clientCertificate = serverCryptoHelper.getOtherCertificate();
        assertNotNull(clientCertificate);
        PublicKey clientPublicKey = serverCryptoHelper.getOtherPublicKey();
        assertNotNull(clientPublicKey);
        if (LOG.isInfoEnabled()) {
            LOG.info("testServerStore: clientPublicKey=" + Base64.encodeBase64String(clientPublicKey.getEncoded()));
        }
        PrivateKey serverPrivateKey = serverCryptoHelper.getMyPrivateKey();
        assertNotNull(serverPrivateKey);
        if (LOG.isInfoEnabled()) {
            LOG.info("testServerStore: serverPrivateKey=" + Base64.encodeBase64String(serverPrivateKey.getEncoded()));
        }
    }
}
