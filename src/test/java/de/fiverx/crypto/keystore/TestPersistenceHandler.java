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

package de.fiverx.crypto.keystore;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.security.KeyStore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests persistence handler
 * <p/>
 * Since reading and writing does a minimal consistency check, this might be enough for now. Add some content assertion, too ...
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 */
public class TestPersistenceHandler {

    private File orig = new File("src/main/resources/crypto/client/client-store.jceks");

    private File temp = new File("build/tmp/client-store.jceks");

    @Before
    public void setUp() throws Exception {
        if (temp.exists()) {
            assertTrue(temp.delete());
        }
        temp.getParentFile().mkdirs();
        Files.copy(orig.toPath(), temp.toPath());
    }

    @Test
    public void testFileHandler() throws Exception {
        FilebasedKeyStorePersistenceHandler handler = new FilebasedKeyStorePersistenceHandler(temp, "clientpw");

        KeyStore keyStore = handler.read();

        long timeWritten = handler.getKeystoreFile().lastModified();
        Thread.sleep(1000); // wait...
        handler.persist(keyStore);
        long timeUpdated = temp.lastModified();
        assertTrue(timeUpdated > timeWritten);
    }

    @Test
    public void testResourceHandler() throws Exception {
        ResourceKeyStorePersistenceHandler handler = new ResourceKeyStorePersistenceHandler("crypto/client/client-store.jceks", "clientpw");
        KeyStore keyStore = handler.read();
        try {
            handler.persist(keyStore);
            fail();
        } catch (KeystoreHandlingException e) {
            ;
        }
    }

    @Test
    public void testBinaryHandler() throws Exception {
        byte[] originalData = readFileAsBytes(orig);
        BinaryKeyStorePersistenceHandler handler = new BinaryKeyStorePersistenceHandler(originalData, "clientpw");
        KeyStore keyStore = handler.read();
        byte[] readData = handler.getKeystoreData();
        assertArrayEquals(originalData, readData);
        handler.persist(keyStore);
        byte[] writtenData = handler.getKeystoreData();
        assertArrayEquals(originalData, writtenData);
    }

    private byte[] readFileAsBytes(File file) throws Exception {
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        byte[] data = new byte[(int)file.length()];
        raf.read(data);
        return data;
    }
}
