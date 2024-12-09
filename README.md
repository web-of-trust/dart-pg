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
const text = 'Hello Dart Privacy Guard!';
const password = 'secret stuff';

final encryptedMessage = OpenPGP.encrypt(
    OpenPGP.createTextMessage(text), passwords: [password]
);
final encrypted = encryptedMessage.armor();
final decryptedMessage = OpenPGP.decrypt(
    OpenPGP.readMessage(encrypted), passwords: [password]
);
final decrypted = decryptedMessage.armor();
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated),
and decryption will use the algorithm used for encryption.
```dart
const text = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encrypt(
    OpenPGP.createTextMessage(text), encryptionKeys: [publicKey]
);
final encrypted = encryptedMessage.armor();

final decryptedMessage = OpenPGP.decrypt(
    OpenPGP.readMessage(encrypted), decryptionKeys: [privateKey]
);
final decrypted = decryptedMessage.armor();
```

Sign message & encrypt with multiple public keys:
```dart
final text = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKeys = Future.wait(
    armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored))
);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encrypt(
    OpenPGP.createTextMessage(text),
    encryptionKeys: publicKeys,
    signingKeys: [privateKey],
);
final encrypted = encryptedMessage.armor();
```

### Sign and verify cleartext
```dart
const text = 'Hello Dart Privacy Guard!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signedMessage = OpenPGP.sign(text, signingKeys: [privateKey]);
final signed = signedMessage.armor();

final verifiedMessage = OpenPGP.verify(signed, verificationKeys: [publicKey]);
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

final signature = OpenPGP.signDetached(text, signingKeys: [privateKey]);
final armored = signature.armor();

final cleartextMessage = OpenPGP.verifyDetached(
    text, armored, verificationKeys: [publicKey]
);
final verifications = cleartextMessage.verifications;
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
final publicKey = privateKey.toPublic;
```

ecdsa type (uses ECDSA algorithm for signing & ECDH algorithm for encryption): Possible values for curve are
secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1 and prime256v1
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.ecc,
    curve: CurveInfo.secp521r1,
);
final publicKey = privateKey.toPublic;
```

eddsa type (uses EdDSA algorithm with ed25519 for signing & ECDH algorithm with curve25519 for encryption):
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.ecc,
);
final publicKey = privateKey.toPublic;
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
