/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'enum/ecc.dart';
import 'enum/key_type.dart';
import 'enum/rsa_key_size.dart';

/// Export high level API for developers.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class OpenPGP {
  bool get isAwesome => true;

  /// Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
  /// The generated primary key will have signing capabilities.
  /// One subkey with encryption capabilities is also generated if `signOnly` is false.
  generateKey(
    Iterator<String> userIDs,
    String passphrase, {
    KeyType type = KeyType.rsa,
    RSAKeySize rsaKeySize = RSAKeySize.normal,
    Ecc curve = Ecc.secp521r1,
    int keyExpiry = 0,
    DateTime? time,
  }) {}

  /// Read OpenPGP public key from armored string.
  /// Return a public key object.
  readPublicKey(String keyData) {}

  /// Read OpenPGP public key list from armored string.
  /// Return iterator of public key objects.
  readPublicKeys(String keyData) {}

  /// Armor multiple public key.
  armorPublicKeys() {}

  /// Read OpenPGP private key from armored string.
  /// Return a private key object.
  readPrivateKey(String keyData) {}

  /// Lock a private key with the given passphrase.
  /// The private key must be decrypted.
  encryptPrivateKey() {}

  /// Read & unlock OpenPGP private key with the given passphrase.
  decryptPrivateKey() {}

  /// Certify an OpenPGP key by a private key.
  /// Return clone of the key object with the new certification added.
  certifyKey() {}

  /// Revoke an OpenPGP key by a private key.
  /// Return clone of the key object with the new revocation signature added.
  revokeKey() {}

  /// Read OpenPGP signature from armored string.
  /// Return a signature object.
  readSignature(String signatureData) {}

  /// Read OpenPGP signed message from armored string.
  /// Return a signed message object.
  readSignedMessage(String messageData) {}

  /// Read OpenPGP encrypted message from armored string.
  /// Return an encrypted message object.
  readEncryptedMessage(String messageData) {}

  /// Read OpenPGP literal message from armored string.
  /// Return a literal message object.
  readLiteralMessage(String messageData) {}

  /// Create new cleartext message object from text.
  createCleartextMessage(String text) {}

  /// Create new literal message object from literal data.
  createLiteralMessage(
    String literalData, {
    String filename = '',
    DateTime? time,
  }) {}

  /// Sign a cleartext message.
  /// Return a signed message object.
  signCleartext() {}

  /// Sign a cleartext message & return detached signature.
  signDetachedCleartext() {}

  /// Sign a message & return signed literal message.
  sign() {}

  /// Sign a message & return detached signature.
  signDetached() {}

  /// Verify signatures of cleartext signed message.
  /// Return verification array.
  verify() {}

  /// Verify detached signatures of cleartext message.
  /// Return verification array.
  verifyDetached() {}

  /// Encrypt a message using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  encrypt() {}

  /// Decrypt a message with the user's private keys, or passwords.
  /// One of `decryptionKeys` or `passwords` must be specified.
  decrypt() {}

  /// Decrypt a armored/binary encrypted string with
  /// the user's private keys, or passwords.
  /// One of `decryptionKeys` or `passwords` must be specified.
  decryptMessage() {}
}
