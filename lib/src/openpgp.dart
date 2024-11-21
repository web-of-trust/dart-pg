/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Export high level API for developers.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class OpenPGP {
  bool get isAwesome => true;

  /// Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
  /// The generated primary key will have signing capabilities.
  /// One subkey with encryption capabilities is also generated if `signOnly` is false.
  generateKey() {}

  /// Read OpenPGP public key from armored/binary string.
  /// Return a public key object.
  readPublicKey() {}

  /// Read OpenPGP public key list from armored/binary string.
  /// Return array of public key objects.
  readPublicKeys() {}

  /// Armor multiple public key.
  armorPublicKeys() {}

  /// Read OpenPGP private key from armored/binary string.
  /// Return a private key object.
  readPrivateKey() {}

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

  /// Read OpenPGP signature from armored/binary string.
  /// Return a signature object.
  readSignature() {}

  /// Read OpenPGP signed message from armored string.
  /// Return a signed message object.
  readSignedMessage() {}

  /// Read OpenPGP encrypted message from armored/binary string.
  /// Return an encrypted message object.
  readEncryptedMessage() {}

  /// Read OpenPGP literal message from armored/binary string.
  /// Return a literal message object.
  readLiteralMessage() {}

  /// Create new cleartext message object from text.
  createCleartextMessage() {}

  /// Create new literal message object from literal data.
  createLiteralMessage() {}

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
  /// One of `decryptionKeys` or `passwords` must be specified
  decrypt() {}

  /// Decrypt a armored/binary encrypted string with
  /// the user's private keys, or passwords.
  /// One of `decryptionKeys` or `passwords` must be specified
  decryptMessage() {}
}
