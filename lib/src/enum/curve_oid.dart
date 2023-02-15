// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'hash_algorithm.dart';
import 'symmetric_algorithm.dart';

enum CurveOid {
  prime256v1('1.2.840.10045.3.1.7'),
  secp384r1('1.3.132.0.34'),
  secp521r1('1.3.132.0.35'),
  secp256k1('1.3.132.0.10'),
  brainpoolp256r1('1.3.36.3.3.2.8.1.1.7'),
  brainpoolp384r1('1.3.36.3.3.2.8.1.1.11'),
  brainpoolp512r1('1.3.36.3.3.2.8.1.1.13'),
  ed25519('1.3.6.1.4.1.11591.15.1'),
  curve25519('1.3.6.1.4.1.3029.1.5.1');

  final String identifierString;

  const CurveOid(this.identifierString);

  String get curveName {
    switch (this) {
      case prime256v1:
        return 'Prime 256 v1';
      case secp384r1:
        return 'Sec P384 r1';
      case secp521r1:
        return 'Sec P521 r1';
      case secp256k1:
        return 'Sec P256 k1';
      case brainpoolp256r1:
        return 'Brainpool P256 r1';
      case brainpoolp384r1:
        return 'Brainpool P384 r1';
      case brainpoolp512r1:
        return 'Brainpool P512 r1';
      case ed25519:
        return 'Ed 25519';
      case curve25519:
        return 'Curve 25519';
    }
  }

  List<int> get identifier {
    switch (this) {
      case prime256v1:
        return [1, 2, 840, 10045, 3, 1, 7];
      case secp384r1:
        return [1, 3, 132, 0, 34];
      case secp521r1:
        return [1, 3, 132, 0, 35];
      case secp256k1:
        return [1, 3, 132, 0, 10];
      case brainpoolp256r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 7];
      case brainpoolp384r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 11];
      case brainpoolp512r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 13];
      case ed25519:
        return [1, 3, 6, 1, 4, 1, 11591, 15, 1];
      case curve25519:
        return [1, 3, 6, 1, 4, 1, 3029, 1, 5, 1];
    }
  }

  HashAlgorithm get hashAlgorithm {
    switch (this) {
      case brainpoolp256r1:
      case curve25519:
      case prime256v1:
      case secp256k1:
        return HashAlgorithm.sha256;
      case brainpoolp384r1:
      case secp384r1:
        return HashAlgorithm.sha384;
      case brainpoolp512r1:
      case ed25519:
      case secp521r1:
        return HashAlgorithm.sha512;
    }
  }

  SymmetricAlgorithm get symmetricAlgorithm {
    switch (this) {
      case brainpoolp256r1:
      case curve25519:
      case ed25519:
      case prime256v1:
      case secp256k1:
        return SymmetricAlgorithm.aes128;
      case brainpoolp384r1:
      case secp384r1:
        return SymmetricAlgorithm.aes192;
      case brainpoolp512r1:
      case secp521r1:
        return SymmetricAlgorithm.aes256;
    }
  }
}
