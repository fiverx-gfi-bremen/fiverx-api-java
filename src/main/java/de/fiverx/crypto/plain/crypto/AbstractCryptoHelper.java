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

package de.fiverx.crypto.plain.crypto;

import de.fiverx.crypto.InternalCryptoException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Security;

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
public abstract class AbstractCryptoHelper {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(AbstractCryptoHelper.class);

    protected Cipher cipher;

    {
        // Java supports RSA signing, but not encryption, therefore another provider comes in place!
        Security.addProvider(new BouncyCastleProvider());
        if (LOG.isInfoEnabled()) {
          LOG.info("instance initializer: Security Provider 'Bouncy Caslte' added!");
        }
    }

    public abstract byte[] encrypt(byte[] data);

    public abstract byte[] decrypt(byte[] encrypted);

    protected byte[] encrypt(Key key, byte[] data) {
        return doFinal(key, data, Cipher.ENCRYPT_MODE);
    }

    protected byte[] decrypt(Key key, byte[] encrypted) {
        return doFinal(key, encrypted, Cipher.DECRYPT_MODE);
    }

    protected byte[] doFinal(Key key, byte[] data, int mode) {
        try {
            cipher.init(mode, key);

            byte[] result = cipher.doFinal(data);

            if (LOG.isInfoEnabled()) {
                LOG.info("doFinal: key=" + key + "; mode=" + (mode == Cipher.ENCRYPT_MODE ? "encrypt" : "decrypt") + "; data=" + Base64.toBase64String(data) + "; result=" + Base64.toBase64String(result));
            }

            return result;
        } catch ( InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new InternalCryptoException(e);
        }
    }

}
