The Dart Privacy Guard (Dart PG) - The OpenPGP library in Dart language
=======================================================================
Dart PG is an implementation of the OpenPGP standard in Dart language. It implements [RFC4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC6637](https://www.rfc-editor.org/rfc/rfc6637), parts of [RFC4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis) and [RFC3156](https://www.rfc-editor.org/rfc/rfc3156).

## Features
* Dart PG allows to encrypt and sign data.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: RSA, DSA, ElGamal, ECDSA, ECDH.
* Support symmetric ciphers: 3DES, IDEA (for backward compatibility), CAST5, Blowfish, Twofish,
  AES-128, AES-192, AES-256, Camellia-128, Camellia-192 and Camellia-256.
* Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224.
* Support compression algorithms: Uncompressed, ZIP, ZLIB.
* Support [ECC](https://wiki.gnupg.org/ECC) algorithms: secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1, prime256v1.

## Getting started
In `Dart` or `flutter` project add the dependency:
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

final encryptedMessage = await OpenPGP.encrypt(Message.createTextMessage(text), passwords: [password]);
final encrypted = encryptedMessage.armor();
final decryptedMessage = await OpenPGP.decrypt(Message.fromArmored(encrypted), passwords: [password]);
final decrypted = decryptedMessage.armor();
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes256 for keys generated), and decryption will use the algorithm used for encryption.
```dart
const text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encrypt(Message.createTextMessage(text), encryptionKeys: [publicKey]);
final encrypted = encryptedMessage.armor();

final decryptedMessage = OpenPGP.decrypt(Message.fromArmored(encrypted), decryptionKeys: [privateKey]);
final decrypted = decryptedMessage.armor();
```

Sign message & encrypt with multiple public keys:
```dart
final text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKeys = armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored));
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final encryptedMessage = OpenPGP.encrypt(Message.createTextMessage(text), encryptionKeys: publicKeys, signingKeys: [privateKey]);
final encrypted = encryptedMessage.armor();
```

### Sign and verify cleartext
```dart
const text = 'Hello Dart PG!';
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
const text = 'Hello Dart PG!';
const passphrase = 'secret stuff';
const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

final publicKey = OpenPGP.readPublicKey(armoredPublicKey);
final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

final signature = OpenPGP.signDetached(text, signingKeys: [privateKey]);
final armored = signature.armor();

final cleartextMessage = OpenPGP.verifyDetached(text, armored, verificationKeys: [publicKey]);
final verifications = cleartextMessage.verifications;
```

### Generate new key pair
rsa keys:
```dart
final userID = [name, '($comment)', '<$email>'].join(' ');
final passphrase = 'secret stuff';
final privateKey = PrivateKey.generate(
    [userID],
    passphrase,
    type: KeyType.rsa,
    bitStrength: 4096,
);
final publicKey = privateKey.toPublic;
```

dsaElGamal keys:
```dart
final userID = [name, '($comment)', '<$email>'].join(' ');
final passphrase = 'secret stuff';
final privateKey = PrivateKey.generate(
    [userID],
    passphrase,
    type: KeyType.dsaElGamal,
    bitStrength: 2048,
);
final publicKey = privateKey.toPublic;
```

ellipticCurve keys (smaller and faster to generate): Possible values for curve are:, secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1 and prime256v1
```dart
final userID = [name, '($comment)', '<$email>'].join(' ');
final passphrase = 'secret stuff';
final privateKey = PrivateKey.generate(
    [userID],
    passphrase,
    type: KeyType.ellipticCurve,
    curve: CurveInfo.prime256v1,
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
