package de.fiverx.crypto.xml;

import de.fiverx.crypto.ConfigHolder;
import de.fiverx.crypto.InternalCryptoException;
import de.fiverx.crypto.keystore.KeyStoreHelper;
import de.fiverx.crypto.plain.crypto.AesCryptoHelper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * user: pknueppe
 * created at: 16.03.2015.
 */
public class FiverxXmlCrypto {

    private KeyStoreHelper keyStoreHelper;

    /**
     * Default Constructor
     */
    public FiverxXmlCrypto() {}

    /**
     * In case that the keys should be pre-configured for this class. You won't have a need to call
     * {@link #encrypt(org.w3c.dom.Document, java.security.PublicKey)} anymore.
     * @param keyStoreHelper
     */
    public FiverxXmlCrypto(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }

    /**
     * encrypt a document with the given pre-configured public key for this class
     * Please note that it is bad code-style to manipulate the document in the parameter directly. Copy the document
     * and encrypt the copy.
     * @param doc the document that shall be encrypted
     * @return the encrypted document
     */
    public Document encrypt(Document doc){
        if (getKeyStoreHelper() == null) {
            throw new SecurityException("cannot decrypt document because keyStoreHelper is 'null'. Please use method:" +
                    " encrypt(Document, PublicKey)");
        }
        try {
            Document document = XmlHelper.cloneDocument(doc);
            // generate a secret key as session key for data encryption (AES/CBC/PKCS7Padding)
            // this is a one time usage key; change to a session key if wanted...
            SecretKey dataKey = AesCryptoHelper.getAesCbcPkcs7PaddingInstance().getSecretKeyInstance();
            // retrieve the partners public RSA key for asymetric key encryption
            PublicKey kek = getKeyStoreHelper().getOtherPublicKey();
            // create a cipher instance
            XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
            // switch to wrap mode since we want to encrypt a key
            keyCipher.init(XMLCipher.WRAP_MODE, kek);
            // key encryption
            EncryptedKey encryptedKey = keyCipher.encryptKey(document, dataKey);
            // create a new cipher for symetric data encryption
            XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_256);
            // initalize cipher for encryption with the  generated key
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
            // encrypted data
            EncryptedData encryptedData = xmlCipher.getEncryptedData();
            // create the key info (used algorithm, ...)
            KeyInfo keyInfo = new KeyInfo(document);
            // add the session key
            keyInfo.add(encryptedKey);
            // add a key name; looks like .NET seems to need one even when could be defaulted to the only one available
            keyInfo.addKeyName("rsaKeyName"); // the keyname should be the api identity, e.g. the ik
            // set the key info
            encryptedData.setKeyInfo(keyInfo);
            // finally, do the encryption job
            xmlCipher.doFinal(document, document);
            return document;
        } catch (Exception e) { // unfortunately, doFinal only throws Exception...
            throw new InternalCryptoException(e);
        }
    }

    /**
     * encrypts the document with the given public key that is not pre-configured in this class
     * Please note that it is bad code-style to manipulate the document in the parameter directly. Copy the document
     * and encrypt the copy.
     * @param doc the document to encrypt
     * @param kek the public key to encrypt the symmetric key that encrypts the document.
     * @return the encrypted document
     */
    public Document encrypt(Document doc, PublicKey kek){
        try {
            Document document = XmlHelper.cloneDocument(doc);
            // generate a secret key as session key for data encryption (AES/CBC/PKCS7Padding)
            // this is a one time usage key; change to a session key if wanted...
            SecretKey dataKey = AesCryptoHelper.getAesCbcPkcs7PaddingInstance().getSecretKeyInstance();
            // create a cipher instance
            XMLCipher keyCipher = XMLCipher.getInstance(ConfigHolder.XmlEncryptionHolder.getXmlAsymmetricEncryption());
            // switch to wrap mode since we want to encrypt a key
            keyCipher.init(XMLCipher.WRAP_MODE, kek);
            // key encryption
            EncryptedKey encryptedKey = keyCipher.encryptKey(document, dataKey);
            // create a new cipher for symetric data encryption
            XMLCipher xmlCipher = XMLCipher.getInstance(ConfigHolder.XmlEncryptionHolder.getXmlSymmetricEncryption());
            // initalize cipher for encryption with the  generated key
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
            // encrypted data
            EncryptedData encryptedData = xmlCipher.getEncryptedData();
            // create the key info (used algorithm, ...)
            KeyInfo keyInfo = new KeyInfo(document);
            // add the session key
            keyInfo.add(encryptedKey);
            // add a key name; looks like .NET seems to need one even when could be defaulted to the only one available
            keyInfo.addKeyName("rsaKeyName"); // the keyname should be the api identity, e.g. the ik
            // set the key info
            encryptedData.setKeyInfo(keyInfo);
            // finally, do the encryption job
            xmlCipher.doFinal(document, document);
            return document;
        } catch (Exception e) { // unfortunately, doFinal only throws Exception...
            throw new InternalCryptoException(e);
        }
    }

    /**
     * This method is responsible for decrypting any xml-document. There is no need to know how the document was
     * created or which algorithms have been used. Just give the encrypted document to this method together with the
     * private key that is needed to decrypt the symmetric key.
     * @param document the encrypted document
     * @param caKek the private key to decrypt the symmetric key that was used for encryption.
     * @return the encrypted document
     */
    public Document decryptDocument (Document document, PrivateKey caKek) {
        try {
            Document encryptedDocument = XmlHelper.cloneDocument(document);
            // enryption should be done for the first element (root element)
            Element encryptedDataElement = (Element) encryptedDocument.getElementsByTagNameNS(
                    EncryptionConstants.EncryptionSpecNS,
                    EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
            // create a new cipher instance (no further information, the cipher will know what to do)
            XMLCipher xmlCipher = XMLCipher.getInstance();
            // initialize the cipher for decryption; no key is provided, since the encrypted XML contains the key and everything else
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            // set the key for key decryption
            xmlCipher.setKEK(caKek);
            // finally, do the decryption job
            xmlCipher.doFinal(encryptedDocument, encryptedDataElement);
            return encryptedDocument;
        } catch (Exception e) {
            throw new InternalCryptoException(e);
        }
    }

    public KeyStoreHelper getKeyStoreHelper() {
        return keyStoreHelper;
    }

    public void setKeyStoreHelper(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }
}
