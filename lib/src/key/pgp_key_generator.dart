// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/pointycastle.dart';

import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';

class PgpKeyGenerator {
  static const _rsaPublicExponent = '65537';

  static AsymmetricKeyPair rsaKeyGenerate([int bits = OpenPGP.minRSABits]) {
    assert(bits >= OpenPGP.minRSABits);

    final keyGen = KeyGenerator('RSA');
    keyGen.init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse(_rsaPublicExponent), bits, 64),
        newSecureRandom(),
      ),
    );
    return keyGen.generateKeyPair();
  }

  static AsymmetricKeyPair ecKeyGenerate([CurveOid curveOid = OpenPGP.preferredEcCurve]) {
    final keyGen = KeyGenerator('EC');
    keyGen.init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(ECDomainParameters(curveOid.name.toLowerCase())),
        newSecureRandom(),
      ),
    );
    return keyGen.generateKeyPair();
  }
}
