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

package de.fiverx.crypto;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;

/**
 * Simple configuration holder with hardcoded elements.
 * <p/>
 * Replace with something more practical.
 * <p/>
 * <h3>Extra-Info</h3>
 *
 * @author zeitler
 * @since v1.0
 */
public class ConfigHolder {

    public static class RsaHolder {

        private static String CONFIGURED_KEY_ALG = "RSA";

        private static String CONFIGURED_CRYPT_ALG = "RSA/ECB/PKCS1Padding";

        public static String getConfiguredKeyAlg() {
            return CONFIGURED_KEY_ALG;
        }

        public static String getConfiguredCryptAlg() {
            return CONFIGURED_CRYPT_ALG;
        }
    }

    public static class AesHolder {

        private static String CONFIGURED_KEY_ALG = "AES";

        private static String CONFIGURED_CRYPT_ALG = "AES/CBC/PKCS7Padding";

        private static int CONFIGURED_KEY_LENGTH = 256;

        public static String getConfiguredKeyAlg() {
            return CONFIGURED_KEY_ALG;
        }

        public static String getConfiguredCryptAlg() {
            return CONFIGURED_CRYPT_ALG;
        }

        public static int getConfiguredKeyLength() {
            return CONFIGURED_KEY_LENGTH;
        }
    }

    public static class SigningHolder {

        private static String CONFIGURED = "SHA256withRSA";

        public static String getConfigured() {
            return CONFIGURED;
        }
    }

    public static class XmlSigningHolder {
        private static final String XML_SIGNATURE_ALGORITHM = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
        private static final String XML_CANONICALZATION_METHOD = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
        private static final String XML_DIGEST_METHOD = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;

        public static String getXmlSignatureAlgorithm() {
            return XML_SIGNATURE_ALGORITHM;
        }

        public static String getXmlCanonicalzationMethod() {
            return XML_CANONICALZATION_METHOD;
        }

        public static String getXmlDigestMethod() {
            return XML_DIGEST_METHOD;
        }
    }

    public static class XmlEncryptionHolder {
        private static final String XML_ASYMMETRIC_ENCRYPTION = XMLCipher.RSA_OAEP;
        private static final String XML_SYMMETRIC_ENCRYPTION = XMLCipher.AES_256;

        public static String getXmlAsymmetricEncryption() {
            return XML_ASYMMETRIC_ENCRYPTION;
        }

        public static String getXmlSymmetricEncryption() {
            return XML_SYMMETRIC_ENCRYPTION;
        }
    }

    public static class Encoding {

        private static String CONFIGURED = "ISO-8859-15";

        public static String getConfigured() {
            return CONFIGURED;
        }
    }

    public static class CustomerValues {

        public static String KEYSTORE_TYPE = "JCEKS";

        public static String CUSTOMER_ALIAS = "theapo";

        public static String CA_ALIAS = "root";
    }

}
