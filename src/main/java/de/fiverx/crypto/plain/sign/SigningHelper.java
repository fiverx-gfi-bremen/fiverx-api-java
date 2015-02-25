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

package de.fiverx.crypto.plain.sign;

import de.fiverx.crypto.ConfigHolder;
import de.fiverx.crypto.InternalCryptoException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

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
public class SigningHelper {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(SigningHelper.class);

    private Signature signature;

    {
        // Java supports RSA signing, but not encryption, therefore another provider comes in place! Even when signing we will add this provider ;-)
        Security.addProvider(new BouncyCastleProvider());
    }

    private SigningHelper(String alg) {
        try {
            signature =  Signature.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalCryptoException(e);
        }
    }

    public static SigningHelper newSigningHelper() {
        return new SigningHelper(ConfigHolder.SigningHolder.getConfigured());
    }

    public byte[] sign(PrivateKey key, byte[] data) {
        try {
            signature.initSign(key, new SecureRandom());
            signature.update(data);
            byte[] sign = signature.sign();

            if (LOG.isInfoEnabled()) {
                LOG.info("sign: data signed! key=" + key + "; signature=" + new String(sign, ConfigHolder.Encoding.getConfigured()));
            }

            return sign;
        } catch ( InvalidKeyException | SignatureException | UnsupportedEncodingException e) {
            throw new InternalCryptoException(e);
        }
    }

    public boolean verifySignature(PublicKey key, byte[] data, byte[] sign) {
        try {
            signature.initVerify(key);
            signature.update(data);
            boolean verify = signature.verify(sign);

            if (LOG.isInfoEnabled()) {
                LOG.info("verifySignature: signature verified! key=" + key + "; sign=" + new String(sign, ConfigHolder.Encoding.getConfigured()) + ", verified=" + verify);
            }

            return verify;
        } catch ( InvalidKeyException | SignatureException | UnsupportedEncodingException e) {
            throw new InternalCryptoException(e);
        }
    }

}
