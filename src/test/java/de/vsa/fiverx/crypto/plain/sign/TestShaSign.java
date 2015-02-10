
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

package de.vsa.fiverx.crypto.plain.sign;

import de.vsa.fiverx.crypto.ConfigHolder;
import de.vsa.fiverx.crypto.xml.CryptoHelper;
import de.vsa.fiverx.crypto.plain.UtilTestHolder;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

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
public class TestShaSign {

    @Test
    public void testSignedByServer() throws Exception {
        signAndVerify(CryptoHelper.serverCryptoHelper(), CryptoHelper.clientCryptoHelper());
    }

    @Test
    public void testSignedByClient() throws Exception {
        signAndVerify(CryptoHelper.clientCryptoHelper(), CryptoHelper.serverCryptoHelper());
    }

    private void signAndVerify(CryptoHelper source, CryptoHelper dest) throws Exception {
        PrivateKey privateKey = source.getMyPrivateKey();
        PublicKey publicKey = dest.getOtherPublicKey();
        SigningHelper signingHelper = SigningHelper.newSigningHelper();

        byte[] signature = signingHelper.sign(privateKey, UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()));
        assertTrue(signingHelper.verifySignature(publicKey, UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()), signature));
    }

}