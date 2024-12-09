Dart PG (Dart Privacy Guard) - The OpenPGP library in Dart language
===================================================================
Dart PG is an implementation of the OpenPGP standard in Dart language.
It implements [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) and
provides encryption with public key or symmetric cryptographic algorithms,
digital signatures, compression, and key management.

## Features
* Support data signing & encryption.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: [RSA](https://www.rfc-editor.org/rfc/rfc3447),
  [ECDSA](https://www.rfc-editor.org/rfc/rfc6979),
  [EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
* Support symmetric ciphers: Blowfish, Twofish,
  [AES](https://www.rfc-editor.org/rfc/rfc3394),
  [Camellia](https://www.rfc-editor.org/rfc/rfc3713).
* Support AEAD ciphers: [EAX](https://seclab.cs.ucdavis.edu/papers/eax.pdf),
  [OCB](https://tools.ietf.org/html/rfc7253),
  [GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf).
* Support hash algorithms: SHA-256, SHA-384, SHA-512, SHA-224, SHA3-256, SHA3-512.
* Support compression algorithms: Zip, Zlib, BZip2.
* Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secp256r1, secp384r1, secp521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [Curve25519, Curve448](https://www.rfc-editor.org/rfc/rfc7748),
  [Ed25519, Ed448](https://www.rfc-editor.org/rfc/rfc8032).
* Support public-key algorithms, symmetric ciphers & hash algorithms
  for signature verification & message decryption (backward compatibility):
  DSA, ElGamal, TripleDES, IDEA, CAST5, MD5, SHA-1, RIPEMD-160.

## Getting started
In `Dart` or `Flutter` project add the dependency:
```yml
dependencies:
  ...
  dart_pg:
```

## Usage

### Encrypt and decrypt data with a password
```dart
const literalText = 'Hello Dart Privacy Guard!';
const password = 'secret stuff';

final encryptedMessage = OpenPGP.encryptCleartext(
    literalText, passwords: [password]
);
final armored = encryptedMessage.armor();
final literalMessage = OpenPGP.decrypt(
    armored, passwords: [password]
);
final literalData = literalMessage.literalData;
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated),
and decryption will use the algorithm used for encryption.
```dart
const literalText = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encryptCleartext(
    literalText, encryptionKeys: [publicKey]
);
final armored = encryptedMessage.armor();

final literalMessage = OpenPGP.decrypt(
    armored, decryptionKeys: [privateKey]
);
final literalData = literalMessage.literalData;
```

Sign message & encrypt with multiple public keys:
```dart
final literalText = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKeys = armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored));
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encryptCleartext(
    literalText,
    encryptionKeys: publicKeys,
    signingKeys: [privateKey],
);
final armored = encryptedMessage.armor();

final literalMessage = OpenPGP.decrypt(
    armored, decryptionKeys: [privateKey]
);
final literalData = literalMessage.literalData;
```

### Sign and verify cleartext
```dart
const text = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signedMessage = OpenPGP.signCleartext(text, signingKeys: [privateKey]);
final armored = signedMessage.armor();

final verifiedMessage = OpenPGP.verify(armored, verificationKeys: [publicKey]);
final verifications = verifiedMessage.verifications;
```

### Detached sign and verify cleartext
```dart
const text = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signature = OpenPGP.signDetachedCleartext(text, signingKeys: [privateKey]);
final armored = signature.armor();

final verifications = OpenPGP.verifyDetached(
    text, armored, verificationKeys: [publicKey]
);
```

### Generate new key pair
rsa type:
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.rsa,
    rsaKeySize: RSAKeySize.normal,
);
final publicKey = privateKey.publicKey;
```

ecdsa type (uses ECDSA algorithm for signing & ECDH algorithm for encryption): Possible values for curve are
secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.ecc,
    curve: Ecc.secp521r1,
);
final publicKey = privateKey.publicKey;
```

eddsa type (uses EdDSA legacy algorithm with ed25519 for signing & ECDH algorithm with curve25519 for encryption):
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.ecc,
    curve: Ecc.ed25519,
);
final publicKey = privateKey.publicKey;
```

Curve25519 key type (uses Ed25519 algorithm for signing & X25519 algorithm for encryption):
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.curve25519,
);
final publicKey = privateKey.publicKey;
```

Curve448 key type (uses Ed448 algorithm for signing & X448 algorithm for encryption):
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.curve448,
);
final publicKey = privateKey.publicKey;
```

## Development
To create your own build of the library, just run the following command after cloning the git repo.
This will download all dependencies, run the tests
```bash
dart pub get && dart test
```

## Licensing
[BSD 3-Clause](LICENSE)

    For the full copyright and license information, please view the LICENSE
    file that was distributed with this source code.
