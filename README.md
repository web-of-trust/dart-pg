Dart PG (Dart Privacy Guard) - The OpenPGP library in Dart language
===================================================================
Dart PG is an implementation of the OpenPGP standard in Dart language.
It implements [RFC4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC6637](https://www.rfc-editor.org/rfc/rfc6637),
parts of [RFC4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis).

## Features
* Dart PG allows to encrypt and sign data.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)),
  [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm),
  [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption),
  [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
* Support symmetric ciphers: 3DES, IDEA (for backward compatibility), CAST5, Blowfish, Twofish,
  [AES-128, AES-192, AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard),
  [Camellia-128, Camellia-192, Camellia-256](https://en.wikipedia.org/wiki/Camellia_(cipher)).
* Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224.
* Support compression algorithms: Uncompressed, ZIP, ZLIB.
* Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) domain parameters:
  [secP256k1, secP384r1, secP521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [prime256v1](https://www.secg.org/sec2-v2.pdf).

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
const text = 'Hello Dart PG!';
const password = 'secret stuff';

final encryptedMessage = await OpenPGP.encrypt(
    OpenPGP.createTextMessage(text), passwords: [password]
);
final encrypted = encryptedMessage.armor();
final decryptedMessage = await OpenPGP.decrypt(
    OpenPGP.readMessage(encrypted), passwords: [password]
);
final decrypted = decryptedMessage.armor();
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated),
and decryption will use the algorithm used for encryption.
```dart
const text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = await OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = await OpenPGP.encrypt(
    OpenPGP.createTextMessage(text), encryptionKeys: [publicKey]
);
final encrypted = encryptedMessage.armor();

final decryptedMessage = await OpenPGP.decrypt(
    OpenPGP.readMessage(encrypted), decryptionKeys: [privateKey]
);
final decrypted = decryptedMessage.armor();
```

Sign message & encrypt with multiple public keys:
```dart
final text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKeys = await Future.wait(
    armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored))
);
final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = await OpenPGP.encrypt(
    OpenPGP.createTextMessage(text),
    encryptionKeys: publicKeys,
    signingKeys: [privateKey],
);
final encrypted = encryptedMessage.armor();
```

### Sign and verify cleartext
```dart
const text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = await OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signedMessage = await OpenPGP.sign(text, signingKeys: [privateKey]);
final signed = signedMessage.armor();

final verifiedMessage = await OpenPGP.verify(signed, verificationKeys: [publicKey]);
final verifications = verifiedMessage.verifications;
```

### Detached sign and verify cleartext
```dart
const text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = await OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signature = await OpenPGP.signDetached(text, signingKeys: [privateKey]);
final armored = signature.armor();

final cleartextMessage = await OpenPGP.verifyDetached(
    text, armored, verificationKeys: [publicKey]
);
final verifications = cleartextMessage.verifications;
```

### Generate new key pair
rsa keys:
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = await OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.rsa,
    rsaKeySize: RSAKeySize.s4096,
);
final publicKey = privateKey.toPublic;
```

dsaElGamal keys:
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = await OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.dsaElGamal,
    dhKeySize: DSAKeySize.l2048n224,
);
final publicKey = privateKey.toPublic;
```

ellipticCurve keys (smaller and faster to generate): Possible values for curve are
secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1 and prime256v1
```dart
const passphrase = 'secret stuff';
final userID = [name, '($comment)', '<$email>'].join(' ');
final privateKey = await OpenPGP.generateKey(
    [userID],
    passphrase,
    type: KeyType.ellipticCurve,
    curve: CurveInfo.secp521r1,
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
