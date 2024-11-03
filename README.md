# INFOSEC_LAB_SEMV_MIT

## DIRECTORY STRUCTURE
```
ISLAB/
|-- packages/
|   |-- asymmetric.py      // RSA, ECC, El-Gamal
|   |-- digitalsign.py     // Schnorr Signature, Diffie-Hellman
|   |-- hashing.py         // MD5, SHA1, SHA256
|   |-- key_mgmt.py        // Key Distribution Centre
|   |-- phe.py             // Paillier Homomorphic Encryption
|   |-- support.py         // Support functions
|   |-- symmetric.py       // DES, Double-Des, DES3, AES(128, 192, 256)
|-- client.py              // Client Script for Socket Programming
|-- server.py              // Server Script for Socket Programming
```

## HOW TO USE
> Run the ```server.py``` script and follow the steps below:
>   1. Pick an Encryption Scheme (RSA, ECC, PHE)
>   2. Enter your name (ID for this session)
>   3. Upon receiving, Confirm status of digital signature verification and decrypted text.

> Run the ```client.py``` script and follow the steps below:
>   1. Enter Plaintext to encrypt
>   2. Get digital signature confirmation from server

## FUTURE WORK
- Add digital-Signature timeout
- implement object-oriented program structure
- improve flexibility of implementation

## CHANGELOG
| Version Number | Log Description |
| -------------- | --------------- |
| V1.0 | committed client-server program and supporting libraries |
