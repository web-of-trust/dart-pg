// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'enum/compression_algorithm.dart';
import 'enum/curve_info.dart';
import 'enum/dsa_key_size.dart';
import 'enum/hash_algorithm.dart';
import 'enum/key_type.dart';
import 'enum/rsa_key_size.dart';
import 'enum/symmetric_algorithm.dart';

import 'type/cleartext_message.dart';
import 'type/message.dart';
import 'type/private_key.dart';
import 'type/public_key.dart';
import 'type/signature.dart';
import 'type/signed_message.dart';

export 'type/cleartext_message.dart';
export 'type/message.dart';
export 'type/private_key.dart';
export 'type/public_key.dart';
export 'type/signature.dart';
export 'type/signed_message.dart';

/// Export high level API for Dart developers.
class OpenPGP {
  static const version = 'Dart PG v1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  static const allowUnauthenticatedMessages = false;

  /// Public key packet version
  static const keyVersion = 4;

  /// Public key encrypted session key packet version
  static const pkeskVersion = 3;

  /// Symmetrically encrypted session key packet version
  static const skeskVersion = 4;

  /// Encrypted integrity protected data packet version
  static const seipVersion = 1;

  /// Default zip/zlib compression level, between 1 and 9
  static const deflateLevel = 6;

  /// Default hash algorithm
  static const preferredHash = HashAlgorithm.sha256;

  /// Default encryption cipher
  static const preferredSymmetric = SymmetricAlgorithm.aes256;

  /// Default compression algorithm
  static const preferredCompression = CompressionAlgorithm.uncompressed;

  /// RSA public exponent
  static const rsaPublicExponent = 65537;

  /// Generate a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  static PrivateKey generateKey(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DSAKeySize dsaKeySize = DSAKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final String? subkeyPassphrase,
    final DateTime? date,
  }) =>
      PrivateKey.generate(
        userIDs,
        passphrase,
        type: type,
        rsaKeySize: rsaKeySize,
        dsaKeySize: dsaKeySize,
        curve: curve,
        keyExpirationTime: keyExpirationTime,
        subkeySign: subkeySign,
        subkeyPassphrase: subkeyPassphrase,
        date: date,
      );

  /// Read an armored & unlock OpenPGP private key with the given passphrase.
  static PrivateKey decryptPrivateKey(
    final String armored,
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) =>
      PrivateKey.fromArmored(armored).decrypt(passphrase, subkeyPassphrases);

  /// Read an armored OpenPGP private key and returns a PrivateKey object
  static PrivateKey readPrivateKey(final String armored) => PrivateKey.fromArmored(armored);

  /// Read an armored OpenPGP public key and returns a PublicKey object
  static PublicKey readPublicKey(final String armored) => PublicKey.fromArmored(armored);

  /// Sign a cleartext message.
  static SignedMessage sign(
    final String text,
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
  }) =>
      SignedMessage.signCleartext(text, signingKeys, date: date);

  /// Sign a cleartext message & return detached signature
  static Signature signDetached(
    final String text,
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
  }) =>
      SignedMessage.signCleartext(text, signingKeys, date: date).signature;

  /// Verify signatures of cleartext signed message
  /// Return signed message with verifications
  static SignedMessage verify(
    final String armored,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) =>
      SignedMessage.fromArmored(armored).verify(verificationKeys, date: date);

  /// Verify detached signatures of cleartext message
  /// Returns cleartext message with verifications
  static CleartextMessage verifyDetached(
    final String text,
    final String armored,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) =>
      CleartextMessage(text).verifySignature(Signature.fromArmored(armored), verificationKeys, date: date);

  /// Read an armored OpenPGP signature and returns a Signature object
  static Signature readSignature(final String armored) => Signature.fromArmored(armored);

  /// Read an armored OpenPGP signed message and returns a SignedMessage object
  static SignedMessage readSignedMessage(final String armored) => SignedMessage.fromArmored(armored);

  /// Read an armored OpenPGP message and returns a Message object
  static Message readMessage(final String armored) => Message.fromArmored(armored);

  /// Create new message object from text
  static Message createTextMessage(
    final String text, {
    final DateTime? time,
  }) =>
      Message.createTextMessage(text, time: time);

  /// Create new message object from binary data.
  static Message createBinaryMessage(
    final Uint8List data, {
    final String filename = '',
    final DateTime? time,
  }) =>
      Message.createBinaryMessage(data, filename: filename, time: time);

  /// Encrypt a message using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  static Message encrypt(
    final Message message, {
    final Iterable<PublicKey> encryptionKeys = const [],
    final Iterable<PrivateKey> signingKeys = const [],
    final Iterable<String> passwords = const [],
    final SymmetricAlgorithm sessionKeySymmetric = OpenPGP.preferredSymmetric,
    final SymmetricAlgorithm encryptionKeySymmetric = OpenPGP.preferredSymmetric,
    final CompressionAlgorithm compression = OpenPGP.preferredCompression,
    final DateTime? date,
  }) =>
      (signingKeys.isNotEmpty)
          ? message.sign(signingKeys, date: date).compress(compression).encrypt(
                encryptionKeys: encryptionKeys,
                passwords: passwords,
                sessionKeySymmetric: sessionKeySymmetric,
                encryptionKeySymmetric: encryptionKeySymmetric,
              )
          : message.compress(compression).encrypt(
                encryptionKeys: encryptionKeys,
                passwords: passwords,
                sessionKeySymmetric: sessionKeySymmetric,
                encryptionKeySymmetric: encryptionKeySymmetric,
              );

  /// Decrypt a message with the user's private key, or a password.
  /// One of `decryptionKeys` or `passwords` must be specified
  /// return object containing decrypted message with verifications
  static Message decrypt(
    final Message message, {
    final Iterable<PrivateKey> decryptionKeys = const [],
    final Iterable<PublicKey> verificationKeys = const [],
    final Iterable<String> passwords = const [],
    final bool allowUnauthenticatedMessages = OpenPGP.allowUnauthenticatedMessages,
    final DateTime? date,
  }) =>
      (verificationKeys.isNotEmpty)
          ? message
              .decrypt(
                decryptionKeys: decryptionKeys,
                passwords: passwords,
                allowUnauthenticatedMessages: allowUnauthenticatedMessages,
              )
              .verify(verificationKeys, date: date)
          : message.decrypt(
              decryptionKeys: decryptionKeys,
              passwords: passwords,
              allowUnauthenticatedMessages: allowUnauthenticatedMessages,
            );
}
