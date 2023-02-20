// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/pointycastle.dart';

import '../../enums.dart';
import '../../helpers.dart';
import 'key_pair_params.dart';
import 'key_params.dart';
import '../../openpgp.dart';

class KeyPairGenerator {
  /// Generate algorithm-specific key parameters
  static KeyPairParams generateKeyPairParams(
    final KeyAlgorithm algorithm, {
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveInfo curve = OpenPGP.preferredCurve,
  }) {
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final keyPair = _generateRSAKeyPair(rsaBits);
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
        final keyPair = _generateECKeyPair(curve);
        final oid = ASN1ObjectIdentifier.fromIdentifierString(curve.identifierString);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDSAPublicParams(oid, q.getEncoded(q.isCompressed).toBigIntWithSign(1)),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.ecdh:
        final keyPair = _generateECKeyPair(curve);
        final oid = ASN1ObjectIdentifier.fromIdentifierString(curve.identifierString);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDHPublicParams(
            oid,
            q.getEncoded(q.isCompressed).toBigIntWithSign(1),
            curve.hashAlgorithm,
            curve.symmetricAlgorithm,
          ),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.elgamal:
        throw UnsupportedError('public key algorithm ${algorithm.name} is unsupported for key generation.');
      default:
        throw Exception('Unknown public key algorithm for key generation.');
    }
  }

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> _generateRSAKeyPair([
    final int bits = OpenPGP.preferredRSABits,
  ]) {
    if (bits < OpenPGP.minRSABits) {
      throw ArgumentError('RSA bits should be at least ${OpenPGP.minRSABits}, got: $bits');
    }

    final keyGen = KeyGenerator('RSA');
    keyGen.init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(OpenPGP.rsaPublicExponent), bits, 64),
        Helper.secureRandom(),
      ),
    );
    final keyPair = keyGen.generateKeyPair();
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
        keyPair.publicKey as RSAPublicKey, keyPair.privateKey as RSAPrivateKey);
  }

  static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateECKeyPair([
    final CurveInfo curve = OpenPGP.preferredCurve,
  ]) {
    switch (curve) {
      case CurveInfo.ed25519:
      case CurveInfo.curve25519:
        throw UnsupportedError('Curve ${curve.name} is unsupported for key generation.');
      default:
        final keyGen = KeyGenerator('EC');
        keyGen.init(
          ParametersWithRandom(
            ECKeyGeneratorParameters(ECDomainParameters(curve.name.toLowerCase())),
            Helper.secureRandom(),
          ),
        );
        final keyPair = keyGen.generateKeyPair();
        return AsymmetricKeyPair<ECPublicKey, ECPrivateKey>(
            keyPair.publicKey as ECPublicKey, keyPair.privateKey as ECPrivateKey);
    }
  }
}
