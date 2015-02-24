# Installation

1. JDK 1.7 or higher must be installed and <code>JAVA_HOME</code> should point to this installation.

2. We are using strong java cryptography, not suitable for the NSA ;-)
    Install the unlimited JCE policy http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html or change the key length within
    <code>de.vsa.fiverx.poc.plain.crypto.AesCryptoHelper</code> from 256 to 128

3. If you are behind a proxy, create or edit <code>gradle.properties</code> within the project directory to ensure connectivity
   Example of content with proxy settings for http and https:
   ```
        systemProp.http.proxyHost=my.proxy
        systemProp.http.proxyPort=8080
        systemProp.https.proxyHost=my.proxy
        systemProp.https.proxyPort=8080
    ```

4. Call 'gradlew test' on Linux or Mac. Call 'gradlew.bat test' on Windows.
    The wrapper will download and install gradle and all needed libraries. The project is compiled and the tests will run. You can see the test report when opening
    <code>build/reports/tests/index.html</code>.

5. (optional) When working with the best IDE, call 'gradlew idea' or (better) just import the build.gradle file as a new project. Otherwise call 'gradlew eclipse' and use eclipse.

6. If you want to publish the project into the local maven repository call 'gradlew publishToMavenLocal' or 'gradlew publish' to publish to a local directory within your build directory

# Some more information

You can find some keys, certificates and keystores in differnt formats within <code>src/main/resources/crypto</code>. The <code>readme.txt</code> file there describes the way they were created.
The keystore passwords are the same as the client key passwords.

This a pure Java API. Groovy is used for testing convenience, only.


# Noteworthy files, packages, sources

| file/package  | description |
| ------------- | ------------- |
| <code>crypto/ca/ca-key.pem</code>                | the servers (CA) private key; password is 'itsokitsok' |
| <code>crypto/ca/ca-root.pem</code>               | the servers certificate (CA) containing the public key |
| <code>crypto/ca/ca-store.jceks</code>            | the servers java keystore containing the CAs private and public key and the users certificate (don't do this in production ;-) |
| <code>crypto/ca/ca-store.p12</code>              | the servers pkcs12 keystore containing the CAs private and public key and the users certificate (don't do this in production ;-) |
| | |
| <code>crypto/client/client-key.pem</code>        | the clients private key; the password is 'clientpw' |
| <code>crypto/client/client-cert.pem</code>       | the clients signed certificate containing the public key. The certificate was signed by our |
| <code>crypto/client/client-store.jceks</code>    | the clients java keystore containing the clients private key, the signed certificate and the root certificate |
| <code>crypto/client/client-store.p12</code>      | the clients pkcs12 keystore containing the clients private key, the signed certificate and the root certificate |
| | |
| <code>crypto/intermediate/client.csr</code>      | the clients certifcates signing request |
| | |
| <code>de.vsa.fiverx.crypto.plain</code>          | a package with classes for dealing with plain cryptography (read keys from keystore, create session keys, encrypt, decrypt, sing, verify signature |
| <code>de.vsa.fiverx.crypto.xml</code>            | a package with classes for dealing wiht xml security |
