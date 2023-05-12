## 1.0.0 (2023-03-21)
- Allows to encrypt and sign data.
- Support key management: key generation, key reading, key decryption.
- Support public-key algorithms: RSA, DSA, ElGamal, ECDSA, EdDSA and ECDH.
- Support symmetric ciphers: 3DES, IDEA (for backward compatibility), CAST5, Blowfish, Twofish, AES-128, AES-192, AES-256, Camellia-128, Camellia-192, Camellia-256.
- Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224.
- Support compression algorithms: Uncompressed, ZIP, ZLIB.
- Support ECC curves: secP256k1, secP384r1, secP521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, curve25519, ed25519, prime256v1.

## 1.0.1 (2023-03-23)
- Remove Crc24 class
- Refactor & format code by Dart formatter

## 1.0.2 (2023-03-23)
- Update pointycastle to 3.7.1
- Use Pointy Castle DESede engine for SymmetricAlgorithm.tripledes
- Use Pointy Castle PKCS1Encoding for RSA & Elgamal session key encryption

## 1.1.0 (2023-04-05)
- Add Camellia key wrapper for ECDH algorithm
- Refactor KeyGenerationType enum

## 1.1.1 (2023-04-24)
- Fix s2k iterated produce key

## 1.1.2 (2023-05-11)
- Pass ParametersWithIV to cipher in SKESK packet
- Refactor session key encryption

## 1.1.3 (2023-05-12)
- Fix decrypt session key in SKESK
