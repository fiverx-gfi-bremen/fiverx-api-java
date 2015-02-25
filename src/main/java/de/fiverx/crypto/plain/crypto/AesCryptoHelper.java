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

import de.fiverx.crypto.ConfigHolder;
import de.fiverx.crypto.InternalCryptoException;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

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
public class AesCryptoHelper extends AbstractCryptoHelper {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(AesCryptoHelper.class);

    private SecretKeySpec secretKeySpec;

    private IvParameterSpec ivSpec;

    private AesCryptoHelper() {
        try {
            cipher = Cipher.getInstance(ConfigHolder.AesHolder.getConfiguredCryptAlg());
            secretKeySpec = generateKey();
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            ivSpec = new IvParameterSpec(cipher.getIV());

            if (LOG.isTraceEnabled()) {
              LOG.trace("AesCryptoHelper: new Helper! secretKeySize=" + secretKeySpec.getEncoded().length + "; ivSize=" + ivSpec.getIV().length);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException  e) {
            throw new InternalCryptoException(e);
        }
    }

    private AesCryptoHelper(byte[] key, byte[] iv) {
        try {
            cipher = Cipher.getInstance(ConfigHolder.AesHolder.getConfiguredCryptAlg());
            secretKeySpec = new SecretKeySpec(key, 0, key.length, ConfigHolder.AesHolder.getConfiguredCryptAlg());
            this.ivSpec = new IvParameterSpec(iv);

            if (LOG.isTraceEnabled()) {
                LOG.trace("AesCryptoHelper: new Helper! secretKeySize=" + secretKeySpec.getEncoded().length + "; ivSize=" + ivSpec.getIV().length);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InternalCryptoException(e);
        }
    }

    public byte[] getSecretKey() {
        return secretKeySpec.getEncoded();
    }

    public byte[] getIv() {
        return ivSpec.getIV();
    }

    public SecretKey getSecretKeyInstance() {
        return secretKeySpec;
    }

    public static AesCryptoHelper getAesCbcPkcs7PaddingInstance() {
        return new AesCryptoHelper();
    }

    public static AesCryptoHelper getAesCbcPkcs7PaddingInstance(byte[] key, byte[] iv) {
        return new AesCryptoHelper(key, iv);
    }

    public byte[] encrypt(byte[] data) {
        return encrypt(secretKeySpec, data);
    }

    public byte[] decrypt(byte[] encrypted) {
        return decrypt(secretKeySpec, encrypted);
    }

    protected byte[] doFinal(Key key, byte[] data, int mode) {
        try {
            cipher.init(mode, key, ivSpec);

            byte[] result = cipher.doFinal(data);

            if (LOG.isInfoEnabled()) {
                LOG.info("doFinal: key=" + key + "; mode=" + (mode == Cipher.ENCRYPT_MODE ? "encrypt" : "decrypt") + "; data=" + Base64.toBase64String(data) + "; result=" + Base64.toBase64String(result));
            }

            return result;
        } catch ( InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new InternalCryptoException(e);
        }
    }

    private SecretKeySpec generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ConfigHolder.AesHolder.getConfiguredKeyAlg());
            keyGenerator.init(ConfigHolder.AesHolder.getConfiguredKeyLength());
            SecretKey secretKey = keyGenerator.generateKey();

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), ConfigHolder.AesHolder.getConfiguredKeyAlg());
            return secretKeySpec;
        } catch (NoSuchAlgorithmException e) {
            throw new InternalCryptoException(e);
        }
    }

}
