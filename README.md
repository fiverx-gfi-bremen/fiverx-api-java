# Installation

1. JDK 1.7 or higher must be installed and JAVA_HOME should point to this installation.

1. We are using strong java cryptography, not suitable for the NSA ;-)
    Install the unlimited JCE policy http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html or change the key length within
    de.vsa.fiverx.poc.plain.crypto.AesCryptoHelper from 256 to 128

1. If you are behind a proxy, create or edit 'gradle.properties' within the project directory to ensure connectivity
   Example of content with proxy settings for http and https:
   ```
        systemProp.http.proxyHost=my.proxy
        systemProp.http.proxyPort=8080
        systemProp.https.proxyHost=my.proxy
        systemProp.https.proxyPort=8080
    ```

1. Call 'gradlew test' on Linux or Mac. Call 'gradlew.bat test' on Windows.
    The wrapper will download and install gradle and all needed libraries. The project is compiled and the tests will run. You can see the test report when opening
    <code>build/reports/tests/index.html</code>.

1. (optional) When working with the best IDE, call 'gradlew idea' or (better) just import the build.gradle file as a new project. Otherwise call 'gradlew eclipse' and use eclipse.


# Some more information

You can find some keys, certificates and keystores in differnt formats within src/main/resources/crypto. The readme.txt file there describes the way they were created.
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
