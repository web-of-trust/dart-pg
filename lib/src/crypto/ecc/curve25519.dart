// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart';

import '../../helpers.dart';

class Curve25519DomainParameters extends ECDomainParametersImpl {
  factory Curve25519DomainParameters() {
    final curve = ECCurve(
      BigInt.parse('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', radix: 16),
      BigInt.parse('2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144', radix: 16),
      BigInt.parse('7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864', radix: 16),
    );

    final g = curve.decodePoint(
      '042aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9'
          .hexToBytes(),
    ) as ECPoint;

    return Curve25519DomainParameters._super(
      'curve25519',
      curve,
      g,
      BigInt.parse('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', radix: 16),
      BigInt.from(8),
      null,
    );
  }

  Curve25519DomainParameters._super(
    String domainName,
    ECCurve curve,
    ECPoint g,
    BigInt n,
    BigInt h,
    List<int>? seed,
  ) : super(domainName, curve, g, n, h, seed);
}
