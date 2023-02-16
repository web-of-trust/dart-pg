// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'enums.dart';
import 'type/cleartext_message.dart';
import 'type/private_key.dart';

class OpenPGP {
  static const version = 'Dart Privacy Guard 1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  static const version5Keys = false;

  /// Default hash algorithm
  static const preferredHashAlgorithm = HashAlgorithm.sha256;

  /// Default encryption cipher
  static const preferredSymmetricAlgorithm = SymmetricAlgorithm.aes256;

  static const preferredCurve = CurveInfo.brainpoolp512r1;

  /// Default RSA bits length
  static const preferredRSABits = 4096;

  /// Min RSA bits length
  static const minRSABits = 2048;

  /// RSA public exponent
  static const rsaPublicExponent = 65537;

  static signDetached(String message, List<PrivateKey> signingKeys) {}

  static sign(
    CleartextMessage message,
    List<PrivateKey> signingKeys, {
    DateTime? date,
    bool detached = false,
  }) {
    if (signingKeys.isEmpty) {
      throw Exception('No signing keys provided');
    }
  }

  /// Generates a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  static PrivateKey generateKey(
    List<String> userIDs,
    String passphrase, {
    KeyType type = KeyType.rsa,
    int rsaBits = OpenPGP.preferredRSABits,
    CurveInfo curve = OpenPGP.preferredCurve,
    int keyExpirationTime = 0,
    bool subkeySign = false,
    String? subkeyPassphrase,
    DateTime? date,
  }) {
    return PrivateKey.generate(
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
  }

  /// Reads an (optionally armored) OpenPGP private key and returns a PrivateKey object
  static PrivateKey readPrivateKey(String armored) {
    return PrivateKey.fromArmored(armored);
  }
}
