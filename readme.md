# A Guide to RSA Encryption in Go

This project mainly quoted from [A Guide to RSA Encryption in Go](https://levelup.gitconnected.com/a-guide-to-rsa-encryption-in-go-1a18d827f35d)

## How to use
* generate private and public keys
    + invoke "./rsa key" to generate private and public keys
    + the keys default write to rsa-private.pem and rsa-public.pem
    + note: the key bits determine the max encrypt text size
* encrypt a message to cipher text
    + invoke "./rsa encrypt 'This is a secret text.'" to use public key to encrypt a cipher text
* decrypt the cipher text
    + invoke "./rsa decrypt XXXXXXXXXXXXXXXX" to use private key to decrypt the cipher text
 