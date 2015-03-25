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

package de.fiverx.util;

import org.apache.log4j.Logger;

import java.io.File;

/**
 * Utility dealing in Java with simple file tasks
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 */
public class FileUtil {

    /**
     * Logger
     */
    private final static Logger LOG = Logger.getLogger(FileUtil.class);

    /**
     * Tries to delete a directory and all its content recursively.
     *
     * @param dir the directory which should be deleted. The file must not be null, must exist, must be writeable and must be a directory.
     * @return <code>true</code>, if everything went fine, <code>false</code> if at least one operations fails.
     * @throws IllegalStateException when a file can't be deleted. The operaton may leave a partially deleted file tree when this exception occurs.
     */
    public static void deleteRecursively(File dir) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("deleteRecursively: deleting file tree! dir=" + dir);
        }

        deleteRecursivelyImpl(dir);
    }

    /**
     * @see {{#deleteRecursively}}
     * @param dir the directory
     * @throws IllegalStateException if a file object could not be deleted.
     */
    private static void deleteRecursivelyImpl(File dir) {
        assert dir != null;
        assert dir.canWrite();
        assert dir.isDirectory();

        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.isDirectory()) {
                deleteRecursivelyImpl(file);
            }
            deleteFile(file);
        }
    }

    /**
     * Deletes a file or emtpy directory.
     * @param file the file to delete
     * @throws IllegalStateException if the file object could not be deleted.
     */
    private static void deleteFile(File file) {
        if (!file.delete()) {
            throw new IllegalStateException("Unable to delete file! file=" + file);
        }
    }
}
