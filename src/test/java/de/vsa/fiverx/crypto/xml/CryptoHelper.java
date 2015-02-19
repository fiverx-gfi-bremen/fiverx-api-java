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
import org.apache.log4j.Logger;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

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
public class CryptoHelper {

    /**
     * Logger
     */
    private final static Logger LOG = Logger.getLogger(CryptoHelper.class);

    private KeyStore keyStore;

    private char[] password;

    private String myAlias;

    private String otherAlias;

    public static CryptoHelper clientCryptoHelper() {
        return new CryptoHelper("crypto/client/client-store.jceks", "theapo", "root", "clientpw");
    }

    public static CryptoHelper serverCryptoHelper() {
        return new CryptoHelper("crypto/ca/ca-store.jceks", "vsaca", "theapo", "itsokitsok");
    }

    public CryptoHelper(String keyStoreResource, String myAlias, String otherAlias, String password) {
        this.password = password.toCharArray();
        this.myAlias = myAlias;
        this.otherAlias = otherAlias;

        keyStore = openKeyStore(keyStoreResource, this.password, "JCEKS");
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public PrivateKey getMyPrivateKey() {
        try {
            return (PrivateKey) keyStore.getKey(myAlias, password);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new InternalCryptoException(e);
        }
    }

    public PublicKey getMyPublicKey() {
        try {
            return keyStore.getCertificate(myAlias).getPublicKey();
        } catch (KeyStoreException e) {
            throw new InternalCryptoException(e);
        }
    }

    public PublicKey getOtherPublicKey() {
        try {
            return keyStore.getCertificate(otherAlias).getPublicKey();
        } catch (KeyStoreException e) {
            throw new InternalCryptoException(e);
        }
    }

    public X509Certificate getMyCertificate() {
        try {
            return (X509Certificate) keyStore.getCertificate(myAlias);
        } catch (KeyStoreException e) {
            throw new InternalCryptoException(e);
        }
    }

    public X509Certificate getOtherCertificate() {
        try {
            return (X509Certificate) keyStore.getCertificate(otherAlias);
        } catch (KeyStoreException e) {
            throw new InternalCryptoException(e);
        }
    }

    private static KeyStore openKeyStore(String resource, char[] password, String type) {
        try(InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(is, password);

            if (LOG.isInfoEnabled()) {
                LOG.info("openKeyStore: keyStore=" + keyStore);
            }

            return keyStore;
        } catch (Exception e) {
            throw new InternalCryptoException(e);
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("CryptoHelper{");
        sb.append("keyStore=").append(keyStore);
        sb.append(", myAlias='").append(myAlias).append('\'');
        sb.append(", otherAlias='").append(otherAlias).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
