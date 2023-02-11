// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/pointycastle.dart';

import '../enums.dart';
import '../helpers.dart';
import 'ec_secret_params.dart';
import 'ecdh_public_params.dart';
import 'ecdsa_public_params.dart';
import 'key_pair_params.dart';
import 'rsa_public_params.dart';
import 'rsa_secret_params.dart';
import '../openpgp.dart';

class KeyPairGenerator {
  /// Generate algorithm-specific key parameters
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
        final publicKey = keyPair.publicKey;
        final privateKey = keyPair.privateKey;

        return KeyPairParams(
          RSAPublicParams(publicKey.modulus!, publicKey.publicExponent!),
          RSASecretParams(
            privateKey.privateExponent!,
            privateKey.p!,
            privateKey.q!,
          ),
        );
      case KeyAlgorithm.ecdsa:
        final keyPair = _generateECKeyPair(curveOid);
        final oid = ASN1ObjectIdentifier.fromIdentifierString(curveOid.identifierString);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDSAPublicParams(oid, q.getEncoded(q.isCompressed).toBigIntWithSign(1)),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.ecdh:
        final keyPair = _generateECKeyPair(curveOid);
        final oid = ASN1ObjectIdentifier.fromIdentifierString(curveOid.identifierString);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDHPublicParams(
            oid,
            q.getEncoded(q.isCompressed).toBigIntWithSign(1),
            curveOid.kdfHash,
            curveOid.kdfSymmetric,
          ),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.elgamal:
        throw Exception('Unsupported public key algorithm for key generation.');
      default:
        throw Exception('Unknown public key algorithm for key generation.');
    }
  }

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> _generateRSAKeyPair([int bits = OpenPGP.preferredRSABits]) {
    assert(bits >= OpenPGP.minRSABits);

    final keyGen = KeyGenerator('RSA');
    keyGen.init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse(OpenPGP.rsaPublicExponent), bits, 64),
        Helper.secureRandom(),
      ),
    );
    return keyGen.generateKeyPair() as AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>;
  }

  static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateECKeyPair(
      [CurveOid curveOid = OpenPGP.preferredEcCurve]) {
    final keyGen = KeyGenerator('EC');
    keyGen.init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(ECDomainParameters(curveOid.name.toLowerCase())),
        Helper.secureRandom(),
      ),
    );
    return keyGen.generateKeyPair() as AsymmetricKeyPair<ECPublicKey, ECPrivateKey>;
  }
}
