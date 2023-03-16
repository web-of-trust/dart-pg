// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';
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
        return _generateRSAKeyPair(rsaKeySize);
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
        if (curve == CurveInfo.curve25519) {
          return _generateCurve25519KeyPair();
        } else {
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
        }
      case KeyAlgorithm.eddsa:
        return _generateEd25519KeyPair();
      case KeyAlgorithm.dsa:
        return _generateDSAKeyPair(dhKeySize);
      case KeyAlgorithm.elgamal:
        return _generateElGamalKeyPair(dhKeySize);
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

  static KeyPairParams _generateRSAKeyPair([
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
    final publicKey = keyPair.publicKey as RSAPublicKey;
    final privateKey = keyPair.privateKey as RSAPrivateKey;

    return KeyPairParams(
      RSAPublicParams(
        publicKey.modulus!,
        publicKey.publicExponent!,
      ),
      RSASecretParams(
        privateKey.privateExponent!,
        privateKey.p!,
        privateKey.q!,
      ),
    );
  }

  static KeyPairParams _generateDSAKeyPair([
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
    final publicKey = keyPair.publicKey as DSAPublicKey;
    final privateKey = keyPair.privateKey as DSAPrivateKey;
    return KeyPairParams(
      DSAPublicParams(
        publicKey.prime,
        publicKey.order,
        publicKey.generator,
        publicKey.y,
      ),
      DSASecretParams(
        privateKey.x,
      ),
    );
  }

  static KeyPairParams _generateElGamalKeyPair([
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
    final publicKey = keyPair.publicKey as ElGamalPublicKey;
    final privateKey = keyPair.privateKey as ElGamalPrivateKey;

    return KeyPairParams(
      ElGamalPublicParams(
        publicKey.prime,
        publicKey.generator,
        publicKey.y,
      ),
      ElGamalSecretParams(
        privateKey.x,
      ),
    );
  }

  static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateECKeyPair([
    final CurveInfo curve = CurveInfo.secp521r1,
  ]) {
    switch (curve) {
      case CurveInfo.curve25519:
      case CurveInfo.ed25519:
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

  static KeyPairParams _generateEd25519KeyPair() {
    final seed = Helper.secureRandom().nextBytes(TweetNaCl.seedSize);
    return KeyPairParams(
      EdDSAPublicParams(
        CurveInfo.ed25519.asn1Oid,
        Uint8List.fromList([
          0x40,
          ...nacl.SigningKey.fromSeed(seed).verifyKey.asTypedList,
        ]).toBigIntWithSign(1),
      ),
      EdSecretParams(seed.toBigIntWithSign(1)),
    );
  }

  static KeyPairParams _generateCurve25519KeyPair() {
    final privateKey = nacl.PrivateKey.fromSeed(
      Helper.secureRandom().nextBytes(TweetNaCl.seedSize),
    );
    return KeyPairParams(
      ECDHPublicParams(
        CurveInfo.curve25519.asn1Oid,
        Uint8List.fromList([
          0x40,
          ...privateKey.publicKey.asTypedList,
        ]).toBigIntWithSign(1),
        CurveInfo.curve25519.hashAlgorithm,
        CurveInfo.curve25519.symmetricAlgorithm,
      ),
      ECSecretParams(
        Uint8List.fromList(privateKey.asTypedList.reversed.toList()).toBigIntWithSign(1),
      ),
    );
  }
}
