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

package de.vsa.fiverx.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Kurzer Satz der die Klasse beschreibt.
 * <p/>
 * Detailierte Beschreibung der Klasse
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 * @deprecated workaround probably not needed any more, since bouncy castle provides a new API
 */
@Deprecated
public class X509UtilWrapper {

    public static ASN1ObjectIdentifier getAlgorithmOID(String algOID) {
        try {
            Class clazz = Thread.currentThread().getContextClassLoader().loadClass("org.bouncycastle.x509.X509Util");

            Method method = clazz.getMethod("getAlgorithmOID");
            method.setAccessible(true);
            return (ASN1ObjectIdentifier) method.invoke(null, algOID);
        } catch (ClassNotFoundException | NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

}
