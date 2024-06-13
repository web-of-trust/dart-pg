// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'enum/compression_algorithm.dart';
import 'enum/curve_info.dart';
import 'enum/dh_key_size.dart';
import 'enum/key_generation_type.dart';
import 'enum/rsa_key_size.dart';
import 'enum/symmetric_algorithm.dart';

import 'type/cleartext_message.dart';
import 'type/message.dart';
import 'type/private_key.dart';
import 'type/public_key.dart';
import 'type/signature.dart';
import 'type/signed_message.dart';

export 'enum/compression_algorithm.dart';
export 'enum/curve_info.dart';
export 'enum/dh_key_size.dart';
export 'enum/key_generation_type.dart';
export 'enum/rsa_key_size.dart';
export 'enum/symmetric_algorithm.dart';

export 'type/cleartext_message.dart';
export 'type/message.dart';
export 'type/private_key.dart';
export 'type/public_key.dart';
export 'type/signature.dart';
export 'type/signed_message.dart';

/// Export high level API for Dart developers.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class OpenPGP {
  /// Generate a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  static Future<PrivateKey> generateKey(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyGenerationType type = KeyGenerationType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final int keyExpirationTime = 0,
    final String? subkeyPassphrase,
    final DateTime? date,
    required Uint8List seed
  }) async =>
      PrivateKey.generate(
        userIDs,
        passphrase,
        type: type,
        rsaKeySize: rsaKeySize,
        dhKeySize: dhKeySize,
        curve: curve,
        keyExpirationTime: keyExpirationTime,
        subkeyPassphrase: subkeyPassphrase,
        date: date,
        seed: seed
      );

  /// Read an armored & unlock OpenPGP private key with the given passphrase.
  static Future<PrivateKey> decryptPrivateKey(
    final String armoredPrivateKey,
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) async =>
      PrivateKey.fromArmored(armoredPrivateKey).decrypt(
        passphrase,
        subkeyPassphrases,
      );

  /// Read an armored OpenPGP private key and returns a PrivateKey object
  static Future<PrivateKey> readPrivateKey(
    final String armoredPrivateKey,
  ) async =>
      PrivateKey.fromArmored(armoredPrivateKey);

  /// Read an armored OpenPGP public key and returns a PublicKey object
  static Future<PublicKey> readPublicKey(
    final String armoredPublicKey,
  ) async =>
      PublicKey.fromArmored(armoredPublicKey);

  /// Read an armored OpenPGP public key list.
  static List<PublicKey> readPublicKeys(final String armoredPublicKeys) {
    return PublicKey.readPublicKeys(armoredPublicKeys);
  }

  /// Sign a cleartext message.
  static Future<SignedMessage> sign(
    final String cleartext,
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.signCleartext(cleartext, signingKeys, date: date);

  /// Sign a cleartext message & return detached signature
  static Future<Signature> signDetached(
    final String cleartext,
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.signCleartext(
        cleartext,
        signingKeys,
        date: date,
      ).then((signedMessage) => signedMessage.signature);

  /// Verify signatures of cleartext signed message
  /// Return signed message with verifications
  static Future<SignedMessage> verify(
    final String armoredSignedMessage,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.fromArmored(armoredSignedMessage).verify(
        verificationKeys,
        date: date,
      );

  /// Verify detached signatures of cleartext message
  /// Returns cleartext message with verifications
  static Future<CleartextMessage> verifyDetached(
    final String cleartext,
    final String armoredSignature,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) async =>
      CleartextMessage(cleartext).verifySignature(
        Signature.fromArmored(armoredSignature),
        verificationKeys,
        date: date,
      );

  /// Read an armored OpenPGP signature and returns a Signature object
  static Future<Signature> readSignature(
    final String armoredSignature,
  ) async =>
      Signature.fromArmored(armoredSignature);

  /// Read an armored OpenPGP signed message and returns a SignedMessage object
  static Future<SignedMessage> readSignedMessage(
    final String armoredSignedMessage,
  ) async =>
      SignedMessage.fromArmored(armoredSignedMessage);

  /// Read an armored OpenPGP message and returns a Message object
  static Future<Message> readMessage(
    final String armoredMessage,
  ) async =>
      Message.fromArmored(armoredMessage);

  /// Create new message object from cleartext
  static Future<Message> createTextMessage(
    final String cleartext, {
    final DateTime? time,
  }) async =>
      Message.createTextMessage(cleartext, time: time);

  /// Create new message object from binary data.
  static Future<Message> createBinaryMessage(
    final Uint8List data, {
    final String filename = '',
    final DateTime? time,
  }) async =>
      Message.createBinaryMessage(data, filename: filename, time: time);

  /// Encrypt a message using public keys, passwords or both at once.
  /// At least one of `encryptionKeys`, `passwords`must be specified.
  /// If signing keys are specified, those will be used to sign the message.
  static Future<Message> encrypt(
    final Message message, {
    final Iterable<PublicKey> encryptionKeys = const [],
    final Iterable<PrivateKey> signingKeys = const [],
    final Iterable<String> passwords = const [],
    final SymmetricAlgorithm sessionKeySymmetric = SymmetricAlgorithm.aes128,
    final SymmetricAlgorithm encryptionKeySymmetric = SymmetricAlgorithm.aes128,
    final CompressionAlgorithm compression = CompressionAlgorithm.uncompressed,
    final bool aeadProtect = false,
    final DateTime? date,
  }) async =>
      (signingKeys.isNotEmpty)
          ? message
              .sign(signingKeys, date: date)
              .then(
                (message) => message.compress(compression),
              )
              .then(
                (message) => message.encrypt(
                  encryptionKeys: encryptionKeys,
                  passwords: passwords,
                  sessionKeySymmetric: sessionKeySymmetric,
                  encryptionKeySymmetric: encryptionKeySymmetric,
                  aeadProtect: aeadProtect,
                ),
              )
          : message.compress(compression).then((message) => message.encrypt(
                encryptionKeys: encryptionKeys,
                passwords: passwords,
                sessionKeySymmetric: sessionKeySymmetric,
                encryptionKeySymmetric: encryptionKeySymmetric,
                aeadProtect: aeadProtect,
              ));

  /// Decrypt a message with the user's private key, or a password.
  /// One of `decryptionKeys` or `passwords` must be specified
  /// return object containing decrypted message with verifications
  static Future<Message> decrypt(
    final Message message, {
    final Iterable<PrivateKey> decryptionKeys = const [],
    final Iterable<PublicKey> verificationKeys = const [],
    final Iterable<String> passwords = const [],
    final bool allowUnauthenticatedMessages = false,
    final DateTime? date,
  }) async =>
      (verificationKeys.isNotEmpty)
          ? message
              .decrypt(
                decryptionKeys: decryptionKeys,
                passwords: passwords,
                allowUnauthenticatedMessages: allowUnauthenticatedMessages,
              )
              .then((message) => message.verify(verificationKeys, date: date))
          : message.decrypt(
              decryptionKeys: decryptionKeys,
              passwords: passwords,
              allowUnauthenticatedMessages: allowUnauthenticatedMessages,
            );
}
