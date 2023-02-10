// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';

class Generator {
  static AsymmetricKeyPair generateRSAKeyPair([int bits = OpenPGP.preferredRSABits]) {
    assert(bits >= OpenPGP.minRSABits);

    final keyGen = KeyGenerator('RSA');
    keyGen.init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse(OpenPGP.rsaPublicExponent), bits, 64),
        Helper.secureRandom(),
      ),
    );
    return keyGen.generateKeyPair();
  }

  static AsymmetricKeyPair generateECKeyPair([CurveOid curveOid = OpenPGP.preferredEcCurve]) {
    final keyGen = KeyGenerator('EC');
    keyGen.init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(ECDomainParameters(curveOid.name.toLowerCase())),
        Helper.secureRandom(),
      ),
    );
    return keyGen.generateKeyPair();
  }
}
