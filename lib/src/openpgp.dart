// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'enums.dart';
import 'type/cleartext_message.dart';
import 'type/private_key.dart';
import 'type/public_key.dart';
import 'type/signature.dart';
import 'type/signed_message.dart';
import 'type/verification.dart';

class OpenPGP {
  static const version = 'Dart PG v1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  static const keyVersion = 4;

  static const pkeskVersion = 3;

  static const skeskVersion = 4;

  /// Default hash algorithm
  static const preferredHash = HashAlgorithm.sha256;

  /// Default encryption cipher
  static const preferredSymmetric = SymmetricAlgorithm.aes256;

  static const preferredCurve = CurveInfo.brainpoolp512r1;

  /// Default RSA bits length
  static const preferredRSABits = 4096;

  /// Min RSA bits length
  static const minRSABits = 2048;

  /// RSA public exponent
  static const rsaPublicExponent = 65537;

  /// Generates a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  static Future<PrivateKey> generateKey(
    final List<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveInfo curve = OpenPGP.preferredCurve,
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final String? subkeyPassphrase,
    final DateTime? date,
  }) async =>
      PrivateKey.generate(
        userIDs,
        passphrase,
        type: type,
        rsaBits: rsaBits,
        curve: curve,
        keyExpirationTime: keyExpirationTime,
        subkeySign: subkeySign,
        subkeyPassphrase: subkeyPassphrase,
        date: date,
      );

  /// Reads an armored & unlock OpenPGP private key with the given passphrase.
  static Future<PrivateKey> decryptPrivateKey(
    final String armored,
    final String passphrase, [
    final List<String> subkeyPassphrases = const [],
  ]) async =>
      PrivateKey.fromArmored(armored).decrypt(passphrase, subkeyPassphrases);

  /// Reads an armored OpenPGP private key and returns a PrivateKey object
  static Future<PrivateKey> readPrivateKey(final String armored) async => PrivateKey.fromArmored(armored);

  /// Reads an armored OpenPGP public key and returns a PublicKey object
  static Future<PublicKey> readPublicKey(final String armored) async => PublicKey.fromArmored(armored);

  /// Signs a cleartext message.
  static Future<SignedMessage> sign(
    final String text,
    final List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.signCleartext(text, signingKeys, date: date);

  /// Signs a cleartext message & return detached signature
  static Future<Signature> signDetached(
    final String text,
    final List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.signCleartext(text, signingKeys, date: date).signature;

  static Future<List<Verification>> verify(
    final String armored,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) async =>
      SignedMessage.fromArmored(armored).verify(verificationKeys, date: date);

  static Future<List<Verification>> verifyDetached(
    final String text,
    final String armored,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) async =>
      CleartextMessage(text).verifySignature(Signature.fromArmored(armored), verificationKeys, date: date);

  /// Reads an armored OpenPGP signature and returns a Signature object
  static Future<Signature> readSignature(final String armored) async => Signature.fromArmored(armored);

  /// Reads an armored OpenPGP signed message and returns a SignedMessage object
  static Future<SignedMessage> readSignedMessage(final String armored) async => SignedMessage.fromArmored(armored);
}
