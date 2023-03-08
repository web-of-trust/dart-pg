The Dart Privacy Guard (Dart PG) - The OpenPGP library in Dart language
=======================================================================
Dart PG is an implementation of the OpenPGP standard in Dart language. It implements [RFC4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC6637](https://www.rfc-editor.org/rfc/rfc6637), parts of [RFC4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis) and [RFC3156](https://www.rfc-editor.org/rfc/rfc3156).

## Features
* Dart PG allows to encrypt and sign data.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: RSA, DSA, ElGamal, ECDSA, ECDH.
* Support symmetric ciphers: 3DES, IDEA (for backward compatibility), CAST5, Blowfish, Twofish, AES-128, AES-192, AES-256, Camellia-128, Camellia-192 and Camellia-256.
* Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224.
* Support compression algorithms: Uncompressed, ZIP, ZLIB.
* Support elliptic curve cryptography: nistp256, nistp384, nistp521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp256k1.

## Getting started
In `Dart` or `flutter` project add the dependency:
```yml
dependencies:
  ...
  dart_pg:
```

## Usage

TODO: Include short and useful examples for package users. Add longer examples
to `/example` folder. 

```dart
const like = 'sample';
```

## Additional information

TODO: Tell users more about the package: where to find more information, how to 
contribute to the package, how to file issues, what response they can expect 
from the package authors, and more.

## Licensing
[BSD 3-Clause](LICENSE)

    For the full copyright and license information, please view the LICENSE
    file that was distributed with this source code.
