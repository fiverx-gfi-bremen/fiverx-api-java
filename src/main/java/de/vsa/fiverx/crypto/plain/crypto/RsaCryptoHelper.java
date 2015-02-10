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

package de.vsa.fiverx.crypto.plain.crypto;

import de.vsa.fiverx.crypto.ConfigHolder;
import de.vsa.fiverx.crypto.InternalCryptoException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
public class RsaCryptoHelper extends AbstractCryptoHelper {

    /**
     * Logger
     */
    private final static Logger LOG = Logger.getLogger(RsaCryptoHelper.class);

    private PrivateKey privateKey;

    private PublicKey publicKey;

    public static RsaCryptoHelper getInstance(String alg, PublicKey publicKey, PrivateKey privateKey) {
        return new RsaCryptoHelper(alg, publicKey, privateKey);
    }

    public static RsaCryptoHelper newInstance(PublicKey publicKey, PrivateKey privateKey) {
        return new RsaCryptoHelper(ConfigHolder.RsaHolder.getConfiguredCryptAlg(), publicKey, privateKey);
    }

    {
        // Java supports RSA signing, but not encryption, therefore another provider comes in place!
        Security.addProvider(new BouncyCastleProvider());
    }

    private RsaCryptoHelper(String alg, PublicKey publicKey, PrivateKey privateKey) {
        try {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            cipher = Cipher.getInstance(alg);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InternalCryptoException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encrypt(publicKey, data);
    }

    @Override
    public byte[] decrypt(byte[] encrypted) {
        return decrypt(privateKey, encrypted);
    }


}
