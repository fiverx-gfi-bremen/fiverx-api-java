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

package de.vsa.fiverx.poc.keystore;

import org.apache.log4j.Logger;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Wraps the keystore for a simple usage.
 * <p/>
 * Deals with a 1:1 perspective right now. In real life, the server must handle several remote aliases, probably a different cert store for the partner certificates.
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 */
public class KeyStoreHelper {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(KeyStoreHelper.class);

    private KeyStorePersistenceHandler persistenceHandler;

    private KeyStore keyStore;

    private String myAlias;

    private String otherAlias;

    private String password;

    public KeyStoreHelper(KeyStorePersistenceHandler persistenceHandler, String password, String myAlias, String otherAlias) {
        assert persistenceHandler != null;

        this.persistenceHandler = persistenceHandler;
        this.keyStore = persistenceHandler.read();
        this.password = password;

        this.myAlias = myAlias;
        this.otherAlias = otherAlias;
    }

    //todo:bz:4.2.2015:move to an AdminKeyStoreHelper instance with write access (adding/removing keys, certs, creating stores ...)
    public void perstistKeyStore() {
        checkConsistency();

        persistenceHandler.persist(keyStore);

        if (LOG.isDebugEnabled()) {
          LOG.debug("perstistKeyStore: persisted! helper=" + this);
        }
    }

    public void updateKeystore() {
        keyStore = persistenceHandler.read();

        checkConsistency();

        if (LOG.isDebugEnabled()) {
          LOG.debug("updateKeystore: updated! helper=" +  this);
        }
    }

    KeyStore getKeyStore() {
        return keyStore;
    }

    public X509Certificate getMyX509Certificate() {
        return getX509Certificate(myAlias);
    }

    public X509Certificate getOtherX509Certificate() {
        return getX509Certificate(otherAlias);
    }

    public PublicKey getMyPublicKey() {
        return getMyX509Certificate().getPublicKey();
    }

    public PrivateKey getMyPrivateKey() {
        try {
            return (PrivateKey) keyStore.getKey(myAlias, password.toCharArray());
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) { // must not happen after consistency check
            throw new KeystoreHandlingException(e);
        }
    }

    public PublicKey getOtherPublicKey() {
        return getOtherX509Certificate().getPublicKey();
    }

    @Override
    public String toString() {
        return "KeyStoreHelper{" +
                "persistenceHandler=" + persistenceHandler +
                ", keyStore=" + keyStore +
                ", myAlias='" + myAlias + '\'' +
                ", myAlias='" + otherAlias + '\'' +
                '}';
    }

    protected void checkConsistency() {
        try {
            Certificate certificate = keyStore.getCertificate(myAlias);
            // exists?
            if (certificate == null) {
                throw new KeystoreHandlingException("Missing certificate! alias=" + myAlias);
            }
            // right type?
            if (!(certificate instanceof X509Certificate)) {
                throw new KeystoreHandlingException("Invalid certificate type! alias=" + myAlias);
            }

            X509Certificate x509Certificate = (X509Certificate) certificate;
            // valid right now?
            x509Certificate.checkValidity();

            try { //todo:bz:4.2.2015:different way to check consistency, but be aware that this class is not final and {@linkplain #getMyPrivateKey} can be overwritten!
                PrivateKey key = getMyPrivateKey();
            } catch (ClassCastException e) {
                throw new KeystoreHandlingException("Invalid key type!", e);
            }
        } catch (KeyStoreException | CertificateExpiredException | CertificateNotYetValidException e) {
            throw new KeystoreHandlingException(e);
        }
    }

    private X509Certificate getX509Certificate(String alias) {
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new KeystoreHandlingException(e);
        }
    }

}
