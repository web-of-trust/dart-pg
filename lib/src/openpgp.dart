// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'enums.dart';
import 'type/private_key.dart';
import 'type/public_key.dart';
import 'type/signature.dart';
import 'type/signed_message.dart';

class OpenPGP {
  static const version = 'Dart PG v1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  static const version5Keys = false;

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
    List<String> userIDs,
    String passphrase, {
    KeyType type = KeyType.rsa,
    int rsaBits = OpenPGP.preferredRSABits,
    CurveInfo curve = OpenPGP.preferredCurve,
    int keyExpirationTime = 0,
    bool subkeySign = false,
    String? subkeyPassphrase,
    DateTime? date,
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
    String armored,
    String passphrase, [
    final List<String> subkeyPassphrases = const [],
  ]) async =>
      PrivateKey.fromArmored(armored).decrypt(passphrase, subkeyPassphrases);

  /// Reads an armored OpenPGP private key and returns a PrivateKey object
  static Future<PrivateKey> readPrivateKey(String armored) async => PrivateKey.fromArmored(armored);

  /// Reads an armored OpenPGP public key and returns a PublicKey object
  static Future<PublicKey> readPublicKey(String armored) async => PublicKey.fromArmored(armored);

  /// Signs a cleartext message.
  static Future<SignedMessage> sign(String text, List<PrivateKey> signingKeys, {DateTime? date}) async =>
      SignedMessage.signCleartext(text, signingKeys, date: date);

  /// Signs a cleartext message & return detached signature
  static Future<Signature> signDetached(String text, List<PrivateKey> signingKeys, {DateTime? date}) async =>
      SignedMessage.signCleartext(text, signingKeys, date: date, detached: true).signature;

  /// Reads an armored OpenPGP signature and returns a Signature object
  static Future<Signature> readSignature(String armored) async => Signature.fromArmored(armored);

  /// Reads an armored OpenPGP signed message and returns a SignedMessage object
  static Future<SignedMessage> readSignedMessage(String armored) async => SignedMessage.fromArmored(armored);
}
