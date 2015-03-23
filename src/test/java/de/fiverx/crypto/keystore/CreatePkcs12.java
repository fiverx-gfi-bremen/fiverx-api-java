/**
 * 
 */
package de.fiverx.crypto.keystore;

/**
 * @author Thomas Probst, ARZ Darmstadt GmbH
 *
 */
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		try {
			System.out.println("### START ###");
			
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			testKeyStore();
			
			System.out.println("### END ###");
			
		} catch (Exception e) {
			System.out.println("### ERROR ###");
			e.printStackTrace();
		}
	}

	public static void testKeyStore() throws Exception{
		
		String filenameP12 =  "test.p12";
		String keyStorePassword = "secret";
		String clientKeyName = "301234561";
		
		try {
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
			OutputStream outputStream = new FileOutputStream(filenameP12);
			outStore.store(outputStream, keyStorePassword.toCharArray());
			outputStream.flush();
			outputStream.close();
			// -------------------------------------------------------

			
			// -- check p12-keystore
			KeyStore inStore = KeyStore.getInstance("PKCS12");
			inStore.load(new FileInputStream(filenameP12), keyStorePassword.toCharArray());
			Key key = outStore.getKey(clientKeyName, keyStorePassword.toCharArray());
			if (privateKeyApo.equals(key) == false) {
				throw new IOException("privKey Apo nicht im Keystore gefunden!");
			}
				
			Certificate[] inChain = outStore.getCertificateChain(clientKeyName);
			if (inChain == null) {
				throw new IOException("CertificateChain(" + clientKeyName + ") nicht gefunden!");
			}
			if (outChain.length != inChain.length) {
				throw new IOException("Chain length error!");
			}
			System.out.println("### OK ###");
			
		} catch (Exception e) {
			System.out.println("### ERROR ###");
			e.printStackTrace();
			throw new AssertionError(e.getMessage());
		}
	}
	
	
	//////////////////////// fiverx-api  File: StoreTest.groovy ///////////////////////////////////////////////
	//////////////////////// fiverx-api  File: StoreTest.groovy ///////////////////////////////////////////////
	//////////////////////// fiverx-api  File: StoreTest.groovy ///////////////////////////////////////////////
	// testX509CreationForCustomer -> split to Server/Customer -> modified return
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

    private static X509Certificate createX509SelfSignedCertificate(KeyPair keyPair, String issuerDnText) throws Exception {
        Date startDate = new Date(new Date().getTime() - 24L*60*60*1000);
        Date expiryDate = new Date(new Date().getTime() + 365L*24L*60*60*1000);

        return createSignedX509Certificate(issuerDnText, issuerDnText, startDate, expiryDate, keyPair.getPrivate(), keyPair.getPublic());
    }
    
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


    private static KeyPair createRSAKeyPair() throws Exception {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), random, 2048, 80));
        AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();
        // used to get proper encoding for the certificate, bz:21.02.2015:not sure if still needed, since the example code is pretty old... guess not...
//        RSAPublicKey pkKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getExponent())
        // JCE format needed for the certificate - because getEncoded() is necessary...
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
