// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum EcCurveOid {
  prime256v1('1.2.840.10045.3.1.7'),
  secp384r1('1.3.132.0.34'),
  secp521r1('1.3.132.0.35'),
  secp256k1('1.3.132.0.10'),
  brainpoolP256r1('1.3.36.3.3.2.8.1.1.7'),
  brainpoolP384r1('1.3.36.3.3.2.8.1.1.11'),
  brainpoolP512r1('1.3.36.3.3.2.8.1.1.13');

  final String identifierString;

  const EcCurveOid(this.identifierString);

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
      case brainpoolP256r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 7];
      case brainpoolP384r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 11];
      case brainpoolP512r1:
        return [1, 3, 36, 3, 3, 2, 8, 1, 1, 13];
    }
  }
}
