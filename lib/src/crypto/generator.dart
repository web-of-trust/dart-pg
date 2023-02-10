// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../enums.dart';
import '../helpers.dart';
import '../key/ec_secret_params.dart';
import '../key/ecdh_public_params.dart';
import '../key/ecdsa_public_params.dart';
import '../key/key_pair_params.dart';
import '../key/rsa_public_params.dart';
import '../key/rsa_secret_params.dart';
import '../openpgp.dart';

class Generator {
  static KeyPairParams generateKeyPairParams(
    KeyAlgorithm algorithm, {
    int bits = OpenPGP.preferredRSABits,
    CurveOid curveOid = OpenPGP.preferredEcCurve,
  }) {
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final keyPair = _generateRSAKeyPair(bits);
        return KeyPairParams(
          RSAPublicParams(keyPair.publicKey as RSAPublicKey),
          RSASecretParams(keyPair.privateKey as RSAPrivateKey),
        );
      case KeyAlgorithm.ecdsa:
        final keyPair = _generateECKeyPair(curveOid);
        return KeyPairParams(
          ECDSAPublicParams(keyPair.publicKey as ECPublicKey),
          ECSecretParams((keyPair.privateKey as ECPrivateKey).d!),
        );
      case KeyAlgorithm.ecdh:
        final keyPair = _generateECKeyPair(curveOid);
        return KeyPairParams(
          ECDHPublicParams(keyPair.publicKey as ECPublicKey, curveOid.kdfHash, curveOid.kdfSymmetric),
          ECSecretParams((keyPair.privateKey as ECPrivateKey).d!),
        );
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.elgamal:
        throw Exception('Unsupported public key algorithm for key generation.');
      default:
        throw Exception('Unknown public key algorithm for key generation.');
    }
  }

  static AsymmetricKeyPair _generateRSAKeyPair([int bits = OpenPGP.preferredRSABits]) {
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

  static AsymmetricKeyPair _generateECKeyPair([CurveOid curveOid = OpenPGP.preferredEcCurve]) {
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
