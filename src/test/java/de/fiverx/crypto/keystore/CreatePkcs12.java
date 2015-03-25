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

/**
 * @author Thomas Probst, ARZ Darmstadt GmbH
 *
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import de.fiverx.util.FileUtil;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


class CertKeyPair {

    private KeyPair keyPair;
    private X509Certificate x509Certificate;
    
	public CertKeyPair(X509Certificate x509Certificate, KeyPair keyPair) {
		this.x509Certificate = x509Certificate;
		this.keyPair = keyPair;
	}
	public KeyPair getKeyPair() {
		return keyPair;
	}
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	public X509Certificate getX509Certificate() {
		return x509Certificate;
	}
	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}
}

public class CreatePkcs12 {

	private final static File PKCS12_FILE = new File("build/tmp/pkcs12", "test.p12");

	@Before
	public void setUp() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		File parent = PKCS12_FILE.getParentFile();
		if (parent.exists()) {
			FileUtil.deleteRecursively(parent);
		}
		parent.mkdir();
	}

	@Test
	public void testKeyStore() throws Exception {
		String keyStorePassword = "secret";
		String clientKeyName = "301234561";
		
		// -- CA
		CertKeyPair caCertKeyPair = testX509CreationForServer();
		KeyPair keyPairCA = caCertKeyPair.getKeyPair();
		PrivateKey caPrivateKey = keyPairCA.getPrivate();
		X509Certificate caCert = caCertKeyPair.getX509Certificate();
		String caIssuerDn = caCert.getIssuerDN().getName();

		// -- Apo
		CertKeyPair customerCertKeyPair = testX509CreationForCustomer(caIssuerDn, caPrivateKey);
		KeyPair keyPairApo = customerCertKeyPair.getKeyPair();
		@SuppressWarnings("unused")
		PublicKey publicKeyApo = keyPairApo.getPublic();
		PrivateKey privateKeyApo = keyPairApo.getPrivate();

		X509Certificate customerCert = customerCertKeyPair.getX509Certificate();

		// cert order is important!!! (client,ca)
		X509Certificate[] outChain = { customerCert, caCert };

		// -------------------------------------------------------
		// -- write p12-keystore (Customer Cert/ CA Cert/priv Key Customer)
		// -------------------------------------------------------
		KeyStore outStore = KeyStore.getInstance("PKCS12");
		outStore.load(null, keyStorePassword.toCharArray());
		outStore.setKeyEntry(
				clientKeyName,
				privateKeyApo,
				keyStorePassword.toCharArray(),
				(java.security.cert.Certificate[]) outChain);

		try(OutputStream outputStream = new FileOutputStream(PKCS12_FILE)) {
			outStore.store(outputStream, keyStorePassword.toCharArray());
		}

		// -- check p12-keystore
		KeyStore inStore = KeyStore.getInstance("PKCS12");
		try(FileInputStream fis = new FileInputStream(PKCS12_FILE)) {
			inStore.load(fis, keyStorePassword.toCharArray());
		}
		Key key = outStore.getKey(clientKeyName, keyStorePassword.toCharArray());

		assertEquals(privateKeyApo, key);

		Certificate[] inChain = outStore.getCertificateChain(clientKeyName);

		assertNotNull(inChain);
		assertEquals(inChain.length, outChain.length);
	}
	
	// return CertKeyPair
    private static CertKeyPair testX509CreationForServer() throws Exception {
        KeyPair caKeyPair = createRSAKeyPair();
        String issuerDnText = "C=DE,O=VSA,OU=PKI,CN=VSA CA";
        X509Certificate x509CertificateCA = createX509SelfSignedCertificate(caKeyPair, issuerDnText);
		return new CertKeyPair(x509CertificateCA, caKeyPair);
    }

	// return CertKeyPair
    private static CertKeyPair testX509CreationForCustomer(String caIssuerDn, PrivateKey caPrivateKey) throws Exception {
    	
        KeyPair customerKeyPair = createRSAKeyPair();
        String dnText = "C=DE,O=APO THEKE,OU=ZENTRALE,CN=APO";
        Date startDate = new Date(new Date().getTime() - 24L*60*60*1000);
        Date expiryDate = new Date(new Date().getTime() + 365L*24L*60*60*1000);
        X509Certificate x509CertificateCustomer = createSignedX509Certificate(
        		dnText, 
        		caIssuerDn, 
        		startDate, 
        		expiryDate, 
        		caPrivateKey, 
        		customerKeyPair.getPublic());
		return new CertKeyPair(x509CertificateCustomer, customerKeyPair);
    }

	//todo:in produktiven Code übernehmen!
    private static X509Certificate createX509SelfSignedCertificate(KeyPair keyPair, String issuerDnText) throws Exception {
        Date startDate = new Date(new Date().getTime() - 24L*60*60*1000);
        Date expiryDate = new Date(new Date().getTime() + 365L*24L*60*60*1000);

        return createSignedX509Certificate(issuerDnText, issuerDnText, startDate, expiryDate, keyPair.getPrivate(), keyPair.getPublic());
    }

	//todo:in produktiven Code übernehmen!
	private static X509Certificate createSignedX509Certificate(String subjectDNText, String issuerDNText, Date startDate, Date expiryDate, PrivateKey signerPrivateKey, PublicKey subjectPublicKey)
    		throws Exception {
        X500Name subjectDN = new X500Name(subjectDNText);
        X500Name issuerDN =  new X500Name(issuerDNText);
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(subjectPublicKey.getEncoded()));
        BigInteger serialNumber = BigInteger.valueOf(new Date().getTime());

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerDN, serialNumber, startDate, expiryDate, subjectDN, subjPubKeyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signerPrivateKey);
        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(contentSigner));
        return x509Certificate;
    }


	//todo:in produktiven Code übernehmen!
    private static KeyPair createRSAKeyPair() throws Exception {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), random, 2048, 80));
        AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
        // and this one for the KeyStore
        PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey.getExponent(),
                        privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
                        privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
        return new KeyPair(pubKey, privKey);
    }
	
}
