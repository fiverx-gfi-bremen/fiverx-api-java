package de.vsa.fiverx.crypto.xml

import de.vsa.fiverx.crypto.keystore.KeyStoreHelper
import de.vsa.fiverx.crypto.keystore.KeyStorePersistenceHandler
import de.vsa.fiverx.crypto.keystore.ResourceKeyStorePersistenceHandler
import org.junit.Before
import org.junit.Test
import org.w3c.dom.Document

import static org.junit.Assert.assertTrue

/**
 * Created by zeitler on 10.02.15.
 */
class TestXmlCrypto {

    private File sourceXmlFile = new File("src/test/resources/data/purchase.xml")

    private File encryptedXmlFile = new File("build/tmp/encrypted.xml")

    private File decryptedXmlFile = new File("build/tmp/decrypted.xml")

    @Before
    public void setUp() {
        if (encryptedXmlFile.exists()) {
            assertTrue(encryptedXmlFile.delete())
        }
        if (decryptedXmlFile.exists()) {
            assertTrue(decryptedXmlFile.delete())
        }
        encryptedXmlFile.getParentFile().mkdirs()
    }

    @Test
    void testXmlEncryptionDecryptionClientToServer() throws Exception {
        // client side initialisation
        KeyStorePersistenceHandler clientKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler("crypto/client/client-store.jceks", "clientpw")
        KeyStoreHelper clientKeyStoreHelper = new KeyStoreHelper(clientKeyStorePersistenceHandler, "clientpw", "theapo", "root")
        XmlCryptorHelper clientXmlCryptoHelper = new XmlCryptoHelperRsaOaepAes256(clientKeyStoreHelper)

        // read the testfile from the filesystem as DOM
        Document xml = XmlHelper.retrieveXml(sourceXmlFile)
        // encrypt
        clientXmlCryptoHelper.encrypt(xml)
        // write xml file
        XmlHelper.writeDocToFile(xml, encryptedXmlFile, false)


        // serverside initialisation
        KeyStorePersistenceHandler serverKeyStorePersistenceHandler = new ResourceKeyStorePersistenceHandler("crypto/ca/ca-store.jceks", "itsokitsok")
        KeyStoreHelper serverKeyStoreHelper = new KeyStoreHelper(serverKeyStorePersistenceHandler, "itsokitsok", "vsaca", "theapo")
        XmlCryptorHelper serverXmlCryptoHelper = new XmlCryptoHelperRsaOaepAes256(serverKeyStoreHelper)

        // read the encrypted XML from file system as DOM from file system (it's a new instance!)
        xml = XmlHelper.retrieveXml(encryptedXmlFile)
        serverXmlCryptoHelper.decrypt(xml)
        // and write the decrypted XML to disk
        XmlHelper.writeDocToFile(xml, decryptedXmlFile, true)

        TestXmlHelper.checkBookingEncoding(decryptedXmlFile)
    }

}
