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

package de.vsa.fiverx.crypto.keystore;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

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
public class FilebasedKeyStorePersistenceHandler extends AbstractKeystorePersistenceHandler {

    /**
    * Logger
    */
    private final static Logger LOG = Logger.getLogger(FilebasedKeyStorePersistenceHandler.class);

    private File file;

    public FilebasedKeyStorePersistenceHandler(File file, String password) {
        super(password);
        this.file = file;
    }

    @Override
    public KeyStore read() {
        try (FileInputStream fis = new FileInputStream(file)){
            KeyStore keyStore = KeyStore.getInstance(getType());
            keyStore.load(fis, getPassword().toCharArray());

            if (LOG.isDebugEnabled()) {
              LOG.debug("read: keystore read! file=" + file);
            }

            return keyStore;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new KeystoreHandlingException(e);
        }
    }

    @Override
    public void persist(KeyStore keystore) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            keystore.store(fos, getPassword().toCharArray());

            if (LOG.isDebugEnabled()) {
              LOG.debug("persist: keystore written! file=" + file);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeystoreHandlingException(e);
        }
    }

    public File getKeystoreFile() {
        return file;
    }
}
