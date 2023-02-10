// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'enums.dart';
import 'type/private_key.dart';

class OpenPGP {
  static const version = 'Dart Privacy Guard 1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  /// Default hash algorithm
  static const preferredHashAlgorithm = HashAlgorithm.sha256;

  /// Default encryption cipher
  static const preferredSymmetricAlgorithm = SymmetricAlgorithm.aes256;

  static const preferredEcCurve = CurveOid.brainpoolp512r1;

  /// Default RSA bits length
  static const preferredRSABits = 4096;

  /// Min RSA bits length
  static const minRSABits = 2048;

  /// RSA public exponent
  static const rsaPublicExponent = '65537';

  static signDetached(String message, List<PrivateKey> signingKeys) {}

  static sign(
    String message,
    List<PrivateKey> signingKeys, {
    DateTime? date,
    bool detached = false,
  }) {
    if (signingKeys.isEmpty) {
      throw Exception('No signing keys provided');
    }
    date = date ?? DateTime.now();
  }

  static generateKey(
    List<String> userIDs,
    String passphrase, {
    KeyType type = KeyType.rsa,
    int rsaBits = OpenPGP.preferredRSABits,
    CurveOid curve = OpenPGP.preferredEcCurve,
  }) {
    if (userIDs.isEmpty) {
      throw Exception('UserIDs are required for key generation');
    }
  }
}

class Awesome {
  bool get isAwesome => true;
}
