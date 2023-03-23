// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Public-Key Algorithms
/// See https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-9.1
enum KeyAlgorithm {
  /// RSA (Encrypt or Sign) [HAC]
  rsaEncryptSign(1),

  /// RSA (Encrypt only) [HAC]
  rsaEncrypt(2),

  /// RSA (Sign only) [HAC]
  rsaSign(3),

  /// Elgamal (Encrypt only) [ELGAMAL] [HAC]
  elgamal(16),

  /// DSA (Sign only) [FIPS186] [HAC]
  dsa(17),

  /// ECDH (Encrypt only) [RFC6637]
  ecdh(18),

  /// ECDSA (Sign only) [RFC6637]
  ecdsa(19),
  elgamalEncryptSign(20),
  diffieHellman(21),

  /// EdDSA (Sign only)
  eddsa(22),

  /// Reserved for AEDH
  aedh(23),

  /// Reserved for AEDSA
  aedsa(24);

  final int value;

  const KeyAlgorithm(this.value);
}
