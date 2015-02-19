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

package de.vsa.fiverx.crypto.keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

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
public class BinaryKeyStorePersistenceHandler extends AbstractKeystorePersistenceHandler {

    private byte[] data;

    public BinaryKeyStorePersistenceHandler(byte[] data, String password) {
        super(password);
        this.data = data;
    }

    @Override
    public KeyStore read() {
        try (ByteArrayInputStream is = new ByteArrayInputStream(data)){
            KeyStore keyStore = KeyStore.getInstance(getType());
            keyStore.load(is, getPassword().toCharArray());
            return keyStore;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeystoreHandlingException(e);
        }
    }

    @Override
    public void persist(KeyStore keystore) {
        try (ByteArrayOutputStream fos = new ByteArrayOutputStream()) {
            keystore.store(fos, getPassword().toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeystoreHandlingException(e);
        }
    }

    public byte[] getKeystoreData() {
        return Arrays.copyOf(data, data.length);
    }
}
