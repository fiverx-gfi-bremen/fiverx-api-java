
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

package de.vsa.fiverx.poc.plain.crypto;

import de.vsa.fiverx.poc.ConfigHolder;
import de.vsa.fiverx.poc.plain.UtilTestHolder;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

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
public class TestAesCryptor {

    @Test
    public void testSimpleEncryptionDecryption() throws Exception {
        AesCryptoHelper aesCryptoHelper = AesCryptoHelper.getAesCbcPkcs7PaddingInstance();

        byte[] encrypted = aesCryptoHelper.encrypt(UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()));

        byte[] decrypted = aesCryptoHelper.decrypt(encrypted);

        assertArrayEquals(UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()), decrypted);
        assertEquals(UtilTestHolder.TEXT, new String(decrypted, ConfigHolder.Encoding.getConfigured()));
    }

    @Test
    public void testEncryptionDecryptionWithNewInstance() throws Exception {
        AesCryptoHelper aesCryptoHelper = AesCryptoHelper.getAesCbcPkcs7PaddingInstance();
        byte[] encrypted = aesCryptoHelper.encrypt(UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()));

        aesCryptoHelper = AesCryptoHelper.getAesCbcPkcs7PaddingInstance(aesCryptoHelper.getSecretKey(), aesCryptoHelper.getIv());
        byte[] decrypted = aesCryptoHelper.decrypt(encrypted);

        assertArrayEquals(UtilTestHolder.TEXT.getBytes(ConfigHolder.Encoding.getConfigured()), decrypted);
        assertEquals(UtilTestHolder.TEXT, new String(decrypted, ConfigHolder.Encoding.getConfigured()));
    }

}
