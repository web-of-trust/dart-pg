// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/pointycastle.dart';

import '../../crypto/asymmetric/elgamal.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/signer/dsa.dart';
import '../../enum/curve_info.dart';
import '../../enum/dh_key_size.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/rsa_key_size.dart';
import '../../helpers.dart';
import 'key_params.dart';

class KeyPairParams {
  /// The number of Miller-Rabin primality tests
  static const mrTests = 64;

  /// RSA public exponent
  static const rsaPublicExponent = 65537;

  final KeyParams publicParams;

  final KeyParams secretParams;

  KeyPairParams(this.publicParams, this.secretParams);

  factory KeyPairParams.generate(
    final KeyAlgorithm algorithm, {
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
  }) {
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final keyPair = _generateRSAKeyPair(rsaKeySize);
        return KeyPairParams(
          RSAPublicParams(
            keyPair.publicKey.modulus!,
            keyPair.publicKey.publicExponent!,
          ),
          RSASecretParams(
            keyPair.privateKey.privateExponent!,
            keyPair.privateKey.p!,
            keyPair.privateKey.q!,
          ),
        );
      case KeyAlgorithm.ecdsa:
        final keyPair = _generateECKeyPair(curve);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDSAPublicParams(
            curve.asn1Oid,
            q.getEncoded(q.isCompressed).toBigIntWithSign(1),
          ),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.ecdh:
        final keyPair = _generateECKeyPair(curve);
        final q = keyPair.publicKey.Q!;
        return KeyPairParams(
          ECDHPublicParams(
            curve.asn1Oid,
            q.getEncoded(q.isCompressed).toBigIntWithSign(1),
            curve.hashAlgorithm,
            curve.symmetricAlgorithm,
          ),
          ECSecretParams(keyPair.privateKey.d!),
        );
      case KeyAlgorithm.dsa:
        final keyPair = _generateDSAKeyPair(dhKeySize);
        return KeyPairParams(
          DSAPublicParams(
            keyPair.publicKey.prime,
            keyPair.publicKey.order,
            keyPair.publicKey.generator,
            keyPair.publicKey.y,
          ),
          DSASecretParams(
            keyPair.privateKey.x,
          ),
        );
      case KeyAlgorithm.elgamal:
        final keyPair = _generateElGamalKeyPair(dhKeySize);
        return KeyPairParams(
          ElGamalPublicParams(
            keyPair.publicKey.prime,
            keyPair.publicKey.generator,
            keyPair.publicKey.y,
          ),
          ElGamalSecretParams(
            keyPair.privateKey.x,
          ),
        );
      default:
        throw UnimplementedError('Unknown public key algorithm for key generation.');
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPairParams &&
          runtimeType == other.runtimeType &&
          publicParams == other.publicParams &&
          secretParams == other.secretParams;

  @override
  int get hashCode => publicParams.hashCode ^ secretParams.hashCode;

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> _generateRSAKeyPair([
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
  ]) {
    final keyGen = KeyGenerator('RSA')
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(
            BigInt.from(rsaPublicExponent),
            rsaKeySize.bits,
            mrTests,
          ),
          Helper.secureRandom(),
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      keyPair.publicKey as RSAPublicKey,
      keyPair.privateKey as RSAPrivateKey,
    );
  }

  static AsymmetricKeyPair<DSAPublicKey, DSAPrivateKey> _generateDSAKeyPair([
    final DHKeySize keySize = DHKeySize.l2048n224,
  ]) {
    final keyGen = DSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          DSAKeyGeneratorParameters(
            keySize.lSize,
            keySize.nSize,
            mrTests,
          ),
          Helper.secureRandom(),
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    return AsymmetricKeyPair<DSAPublicKey, DSAPrivateKey>(
      keyPair.publicKey as DSAPublicKey,
      keyPair.privateKey as DSAPrivateKey,
    );
  }

  static AsymmetricKeyPair<ElGamalPublicKey, ElGamalPrivateKey> _generateElGamalKeyPair([
    final DHKeySize keySize = DHKeySize.l2048n224,
  ]) {
    final keyGen = ElGamalKeyGenerator()
      ..init(
        ParametersWithRandom(
          ElGamalKeyGeneratorParameters(
            keySize.lSize,
            keySize.nSize,
            mrTests,
          ),
          Helper.secureRandom(),
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    return AsymmetricKeyPair<ElGamalPublicKey, ElGamalPrivateKey>(
      keyPair.publicKey as ElGamalPublicKey,
      keyPair.privateKey as ElGamalPrivateKey,
    );
  }

  static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateECKeyPair([
    final CurveInfo curve = CurveInfo.secp521r1,
  ]) {
    switch (curve) {
      case CurveInfo.ed25519:
      case CurveInfo.curve25519:
        throw UnsupportedError('Curve ${curve.name} is unsupported for key generation.');
      default:
        final keyGen = KeyGenerator('EC')
          ..init(
            ParametersWithRandom(
              ECKeyGeneratorParameters(ECDomainParameters(curve.name.toLowerCase())),
              Helper.secureRandom(),
            ),
          );
        final keyPair = keyGen.generateKeyPair();
        return AsymmetricKeyPair<ECPublicKey, ECPrivateKey>(
          keyPair.publicKey as ECPublicKey,
          keyPair.privateKey as ECPrivateKey,
        );
    }
  }
}
