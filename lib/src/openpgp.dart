/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'common/config.dart';
import 'common/extensions.dart';
import 'enum/compression_algorithm.dart';
import 'enum/ecc.dart';
import 'enum/key_type.dart';
import 'enum/rsa_key_size.dart';
import 'enum/symmetric_algorithm.dart';
import 'key/base_key.dart';
import 'message/base_message.dart';
import 'type/cleartext_message.dart';
import 'type/key.dart';
import 'type/literal_message.dart';
import 'type/packet_list.dart';
import 'type/session_key.dart';

export 'common/config.dart';
export 'common/helpers.dart';
export 'key/base_key.dart';
export 'message/base_message.dart';

/// Export high level API for developers.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class OpenPGP {
  /// Generate a new OpenPGP key pair.
  /// Support RSA, ECC, Curve25519 and Curve448 key types.
  /// The generated primary key will have signing capabilities.
  /// One subkey with encryption capabilities is also generated if `signOnly` is false.
  static PrivateKeyInterface generateKey(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.normal,
    final Ecc curve = Ecc.secp521r1,
    final int keyExpiry = 0,
    final bool signOnly = false,
    final DateTime? time,
  }) {
    return PrivateKey.generate(
      userIDs,
      passphrase,
      type: type,
      rsaKeySize: rsaKeySize,
      curve: curve,
      keyExpiry: keyExpiry,
      signOnly: signOnly,
      time: time,
    );
  }

  /// Read OpenPGP public key from armored string.
  /// Return a public key object.
  static KeyInterface readPublicKey(final String armored) {
    return PublicKey.fromArmored(armored);
  }

  /// Read OpenPGP public key list from armored string.
  /// Return iterator of public key objects.
  static Iterable<KeyInterface> readPublicKeys(final String armored) {
    return PublicKey.readPublicKeys(armored);
  }

  /// Armor multiple public key.
  static String armorPublicKeys(final Iterable<KeyInterface> keys) {
    return PublicKey.armorPublicKeys(keys);
  }

  /// Read OpenPGP private key from armored string.
  /// Return a private key object.
  static PrivateKeyInterface readPrivateKey(final String armored) {
    return PrivateKey.fromArmored(armored);
  }

  /// Lock a private key with the given passphrase.
  /// The private key must be decrypted.
  static PrivateKeyInterface encryptPrivateKey(
    final PrivateKeyInterface privateKey,
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    return privateKey.encrypt(passphrase, subkeyPassphrases);
  }

  /// Read & unlock OpenPGP private key with the given passphrase.
  static PrivateKeyInterface decryptPrivateKey(
    final String armored,
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    return PrivateKey.fromArmored(armored).decrypt(
      passphrase,
      subkeyPassphrases,
    );
  }

  /// Read OpenPGP signature from armored string.
  /// Return a signature object.
  static SignatureInterface readSignature(final String armored) {
    return Signature.fromArmored(armored);
  }

  /// Read OpenPGP signed message from armored string.
  /// Return a signed message object.
  static SignedMessageInterface readSignedMessage(final String armored) {
    return SignedMessage.fromArmored(armored);
  }

  /// Read OpenPGP literal message from armored string.
  /// Return a literal message object.
  static LiteralMessageInterface readLiteralMessage(final String armored) {
    return LiteralMessage.fromArmored(armored);
  }

  /// Read OpenPGP encrypted message from armored string.
  /// Return an encrypted message object.
  static EncryptedMessageInterface readEncryptedMessage(final String armored) {
    return EncryptedMessage.fromArmored(armored);
  }

  /// Create new cleartext message object from text.
  static CleartextMessageInterface createCleartextMessage(final String text) {
    return CleartextMessage(text);
  }

  /// Create new literal message object from literal data.
  static LiteralMessageInterface createLiteralMessage(
    final Uint8List literalData, {
    final String filename = '',
    final DateTime? time,
  }) {
    return LiteralMessage.fromLiteralData(
      literalData,
      filename: filename,
      time: time,
    );
  }

  /// Sign a cleartext message.
  /// Return a signed message object.
  static SignedCleartextMessageInterface signCleartext(
    final String text,
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return CleartextMessage(text).sign(
      signingKeys,
      recipients: recipients,
      notationData: notationData,
      time: time,
    );
  }

  /// Sign a cleartext message & return detached signature.
  static SignatureInterface signDetachedCleartext(
    final String text,
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return CleartextMessage(text).signDetached(
      signingKeys,
      recipients: recipients,
      notationData: notationData,
      time: time,
    );
  }

  /// Sign a message & return signed literal message.
  static LiteralMessageInterface sign(
    final LiteralMessageInterface message,
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return message.sign(
      signingKeys,
      recipients: recipients,
      notationData: notationData,
      time: time,
    );
  }

  /// Sign a message & return detached signature.
  static SignatureInterface signDetached(
    final LiteralMessageInterface message,
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return message.signDetached(
      signingKeys,
      recipients: recipients,
      notationData: notationData,
      time: time,
    );
  }

  /// Verify signatures of cleartext signed message.
  /// Return verification array.
  static Iterable<VerificationInterface> verify(
    final String armored,
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]) {
    return readSignedMessage(armored).verify(
      verificationKeys,
      time,
    );
  }

  /// Verify detached signatures of cleartext message.
  /// Return verification array.
  static Iterable<VerificationInterface> verifyDetached(
    final String text,
    final String signature,
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]) {
    return createCleartextMessage(text).verifyDetached(
      verificationKeys,
      readSignature(signature),
      time,
    );
  }

  /// Verify signatures of signed literal message.
  /// Return verification array.
  static Iterable<VerificationInterface> verifyInline(
    final String armored,
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]) {
    return readLiteralMessage(armored).verify(
      verificationKeys,
      time,
    );
  }

  /// Encrypt a message using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  static EncryptedMessageInterface encrypt(
    final LiteralMessageInterface message, {
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final Iterable<PrivateKeyInterface> signingKeys = const [],
    final SymmetricAlgorithm? symmetric,
    final CompressionAlgorithm? compression,
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return signingKeys.isEmpty
        ? message.compress(compression).encrypt(
              encryptionKeys: encryptionKeys,
              passwords: passwords,
              symmetric: symmetric,
            )
        : message
            .sign(
              signingKeys,
              recipients: encryptionKeys,
              notationData: notationData,
              time: time,
            )
            .compress(compression)
            .encrypt(
              encryptionKeys: encryptionKeys,
              passwords: passwords,
              symmetric: symmetric,
            );
  }

  /// Encrypt binary data using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  static EncryptedMessageInterface encryptBinaryData(
    final Uint8List bytes, {
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final Iterable<PrivateKeyInterface> signingKeys = const [],
    final SymmetricAlgorithm? symmetric,
    final CompressionAlgorithm? compression,
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return encrypt(
      createLiteralMessage(bytes),
      encryptionKeys: encryptionKeys,
      passwords: passwords,
      signingKeys: signingKeys,
      symmetric: symmetric,
      notationData: notationData,
      time: time,
    );
  }

  /// Encrypt cleartext using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  static EncryptedMessageInterface encryptCleartext(
    final String cleartext, {
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final Iterable<PrivateKeyInterface> signingKeys = const [],
    final SymmetricAlgorithm? symmetric,
    final CompressionAlgorithm? compression,
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    return encrypt(
      createLiteralMessage(cleartext.toBytes()),
      encryptionKeys: encryptionKeys,
      passwords: passwords,
      signingKeys: signingKeys,
      symmetric: symmetric,
      notationData: notationData,
      time: time,
    );
  }

  /// Decrypt a armored encrypted message with
  /// the user's private keys, or passwords.
  /// One of `decryptionKeys` or `passwords` must be specified.
  static LiteralMessageInterface decrypt(
    final String armored, {
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    return decryptMessage(
      readEncryptedMessage(armored),
      decryptionKeys: decryptionKeys,
      passwords: passwords,
    );
  }

  /// Decrypt an encrypted message with the user's private keys, or passwords.
  /// One of `decryptionKeys` or `passwords` must be specified.
  static LiteralMessageInterface decryptMessage(
    final EncryptedMessageInterface message, {
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    return message.decrypt(
      decryptionKeys: decryptionKeys,
      passwords: passwords,
    );
  }

  /// Generate a new session key object.
  /// Checking the algorithm preferences of the passed encryption keys.
  static SessionKeyInterface generateSessionKey(
    final Iterable<KeyInterface> encryptionKeys, [
    final SymmetricAlgorithm? symmetric,
  ]) {
    return LiteralMessage.generateSessionKey(
      encryptionKeys,
      symmetric ?? Config.preferredSymmetric,
    );
  }

  /// Encrypt a session key either with public keys, passwords, or both at once.
  static PacketListInterface encryptSessionKey(
    SessionKeyInterface sessionKey, {
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    return LiteralMessage.encryptSessionKey(
      sessionKey,
      encryptionKeys: encryptionKeys,
      passwords: passwords,
    );
  }

  /// Decrypt symmetric session keys using private keys or passwords (not both).
  static SessionKeyInterface decryptSessionKey(
    final PacketListInterface packetList, {
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    return EncryptedMessage.decryptSessionKey(
      packetList,
      decryptionKeys: decryptionKeys,
      passwords: passwords,
    );
  }
}
