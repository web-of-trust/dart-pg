/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/config.dart';
import 'key_version.dart';
import 'profile.dart';

/// Public key algorithms enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum KeyAlgorithm {
  /// RSA (Encrypt or Sign) [HAC]
  rsaEncryptSign(1),

  /// RSA (Encrypt only) [HAC]
  rsaEncrypt(2),

  /// RSA (Sign only) [HAC]
  rsaSign(3),

  /// ElGamal (Encrypt only) [ELGAMAL] [HAC]
  elgamal(16),

  /// DSA (Sign only) [FIPS186] [HAC]
  dsa(17),

  /// ECDH (Encrypt only) [RFC6637]
  ecdh(18),

  /// ECDSA (Sign only) [RFC6637]
  ecdsa(19),
  elgamalEncryptSign(20),
  diffieHellman(21),

  /// EdDSA Legacy (Sign only)
  eddsaLegacy(22),

  /// Reserved for AEDH
  aedh(23),

  /// Reserved for AEDSA
  aedsa(24),

  /// X25519 (Encrypt only)
  x25519(25),

  /// X448 (Encrypt only)
  x448(26),

  /// Ed25519 (Sign only)
  ed25519(27),

  /// Ed448 (Sign only)
  ed448(28);

  final int value;

  const KeyAlgorithm(this.value);

  bool get forSigning => switch (this) {
        rsaEncrypt || elgamal || ecdh || aedh || x25519 || x448 => false,
        _ => true,
      };

  bool get forEncryption => switch (this) {
        rsaSign || dsa || eddsaLegacy || aedsa || ed25519 || ed448 => false,
        _ => true,
      };

  int get keyVersion => switch (this) {
        x25519 || x448 || ed25519 || ed448 => KeyVersion.v6.value,
        _ => Config.useProfile == Profile.rfc9580 ? KeyVersion.v6.value : KeyVersion.v4.value,
      };
}
