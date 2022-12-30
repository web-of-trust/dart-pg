// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Public-Key Algorithms
/// See https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-9.1
enum KeyAlgorithm {
  rsaEncryptSign(1),
  rsaEncrypt(2),
  rsaSign(3),
  elgamal(16),
  dsa(17),
  ecdh(18),
  ecdsa(19),
  elgamalEncryptSign(20),
  diffieHellman(21),
  eddsa(22),
  aedh(23),
  aedsa(24);

  final int value;

  const KeyAlgorithm(this.value);
}
