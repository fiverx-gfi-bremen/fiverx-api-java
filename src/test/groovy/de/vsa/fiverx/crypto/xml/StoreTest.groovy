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

package de.vsa.fiverx.crypto.xml

import groovy.util.logging.Log4j
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Before
import org.junit.Test

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.text.SimpleDateFormat

import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertTrue

/**
 * Created by zeitler on 20.01.15.
 */
@Log4j
class StoreTest {

    private SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.YYYY HH:mm:ss.SSS");

    private File dir = new File("build/tmp/store")

    private File caStoreFile = new File(dir, "caStore")

    private SecureRandom random = SecureRandom.getInstance("SHA1PRNG")

    @Before
    void setUp() {
        Security.addProvider(new BouncyCastleProvider())

        if (dir.exists()) {
            assertTrue dir.deleteDir()
        }
        assertTrue dir.mkdirs()
    }

    @Test
    void testRSAKeyPair() {
        KeyPair keyPair = createRSAKeyPair()

        assertNotNull keyPair // todo:bz:01.02.2015:check for consistency
    }

    @Test
    void testX509CreationForCA() {
        KeyPair keyPair = createRSAKeyPair()
        String issuerDnText = "C=DE,O=VSA,OU=PKI,CN=VSA CA"
        X509Certificate x509Certificate = createX509SelfSignedCertificate(keyPair, issuerDnText)

        assertNotNull x509Certificate // todo:bz:01.02.2015:check for consistency
    }

    @Test
    void testX509CreationForCustomer() {
        KeyPair caKeyPair = createRSAKeyPair()
        KeyPair customerKeyPair = createRSAKeyPair()
        String issuerDnText = "C=DE,O=VSA,OU=PKI,CN=VSA CA"
        X509Certificate x509CertificateCA = createX509SelfSignedCertificate(caKeyPair, issuerDnText)

        String dnText = "C=DE,O=APO THEKE,OU=ZENTRALE,CN=APO"
        Date startDate = dateFormat.parse("01.01.2015 00:00:00.000")
        Date expiryDate = dateFormat.parse("31.12.2018 24:00:00.000")
        String issuerDn = x509CertificateCA.issuerDN.name
        X509Certificate x509CertificateCustomer = createSignedX509Certificate(dnText, issuerDn, startDate, expiryDate, caKeyPair.private, customerKeyPair.public)

        assertNotNull x509CertificateCustomer // todo:bz:01.02.2015:check for consistency
    }



    private KeyPair createRSAKeyPair() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator()
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), random, 2048, 80))
        AsymmetricCipherKeyPair keypair = gen.generateKeyPair()
        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic()
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate()
        // used to get proper encoding for the certificate, bz:21.02.2015:not sure if still needed, since the example code is pretty old... guess not...
//        RSAPublicKey pkKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getExponent())
        // JCE format needed for the certificate - because getEncoded() is necessary...
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()))
        // and this one for the KeyStore
        PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey.getExponent(),
                        privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
                        privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()))
        return new KeyPair(pubKey, privKey)
    }

    private X509Certificate createX509SelfSignedCertificate(KeyPair keyPair, String issuerDnText) {
        Date startDate = dateFormat.parse("01.01.2015 00:00:00.000")
        Date expiryDate = dateFormat.parse("31.12.2018 24:00:00.000")

        return createSignedX509Certificate(issuerDnText, issuerDnText, startDate, expiryDate, keyPair.private, keyPair.public)
    }

    private X509Certificate createSignedX509Certificate(String subjectDNText, String issuerDNText, Date startDate, Date expiryDate, PrivateKey signerPrivateKey, PublicKey subjectPublicKey) {
        X500Name subjectDN = new X500Name(subjectDNText)
        X500Name issuerDN =  new X500Name(issuerDNText)
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(subjectPublicKey.encoded))
        BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()))

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerDN, serialNumber, startDate, expiryDate, subjectDN, subjPubKeyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signerPrivateKey)
        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(contentSigner))
        return x509Certificate
    }

    private void createKeystore(File keystoreFile, String alias, PrivateKey privateKey, String password, X509Certificate[] certificateChain) {
        KeyStore keystore = KeyStore.getInstance("JCEKS")
        keystore.load(null)
        keystore.setKeyEntry(alias, privateKey, password.toCharArray(), certificateChain)

        new FileOutputStream(keystoreFile).withStream {
            keystore.store(it, password.toCharArray())
        }
    }

    private void addX509CertificateToKeystore(File keystorefile, String password, String alias, X509Certificate certificate) {
        KeyStore keystore = KeyStore.getInstance("JCEKS")
        new FileInputStream(keystorefile).withStream() {
            keystore.load(it, password.toCharArray())
        }
        keystore.setCertificateEntry(alias, certificate)
        new FileOutputStream(keystorefile).withStream() {
            keystore.store(it, password.toCharArray())
        }
    }

}
