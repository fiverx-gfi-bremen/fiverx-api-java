CRYPTO


1. CA Authority erstellen (geheimer private key)
openssl genrsa -aes256 -out ca-key.pem 2048

Passwort: itsokitsok

2. Root-Zertifikat erstellen
openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 3650 -out ca-root.pem -sha256

3. Client-Keystore erstellen (mit geheimen privater key)
keytool -genkey -keystore client-store.jceks -storetype JCEKS -storepass clientpw -alias theapo -keypass clientpw -keyalg RSA -keysize 2048

4. Certification Request erstellen
keytool -certreq -keystore client-store.jceks -storetype JCEKS -alias theapo -file client.csr -keypass clientpw -storepass clientpw

(keyalg?, sigalg?)

5. Client Zertifikat mit Public Key ausstellen (1000 Tage gültig)
openssl x509 -req -in client.csr -CA ca-root.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 1000 -sha256

6. Root-Zertifikat in Client-Keystore (JKS) ablegen
keytool -import -trustcacerts -alias root -file ca-root.pem -keystore client-store.jceks -storepass clientpw -storetype JCEKS

7. Userzertifikat importieren
keytool -import -trustcacerts -alias theapo -file client-cert.pem -keystore client-store.jceks -storepass clientpw -keypass clientpw -storetype JCEKS

8. Angucken
keytool -list -keystore client-store.jceks -storepass clientpw -storetype JCEKS

9. PKCS12 Keystore für CA erstellen
cat ca-root.pem ca-key.pem > ca-rootandkey.pem
openssl pkcs12 -export -in ca-rootandkey.pem -out ca-store.p12 -name vsaca -noiter -nomaciter

Passwort: itsokitsok

10. PKCS12 in JCEKS konvertieren
keytool -importkeystore -srckeystore ca-store.p12 -destkeystore ca-store.jceks -srcstoretype pkcs12 -deststoretype jceks -srcstorepass itsokitsok -deststorepass itsokitsok

11. Angucken
keytool -list -keystore ca-store.jceks -storepass itsokitsok -storetype JCEKS

12. PEM -> DER
openssl pkcs8 -topk8 -nocrypt -in client-key.pem -inform PEM -out client-key.der -outform DER

13. Client Zertifikat in Server Keystore einbringen
keytool -import -trustcacerts -alias theapo -file client-cert.pem -keystore ca-store.jceks -storepass itsokitsok -storetype JCEKS

14. Client Keystore in PKCS12 Konvertieren
keytool -importkeystore -srckeystore client-store.jceks -destkeystore client-store.p12 -srcstoretype jceks -deststoretype pkcs12 -srcstorepass clientpw -deststorepass clientpw
(Fehler beim Import für 'root'. Wurde mit KeyStore Explorer repariert (Aliasname fehlte am Zertifikat)

Besuche http://keystore-explorer.sourceforge.net/ für den ultimativen Spaß!
