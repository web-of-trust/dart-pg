/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../enum/hash_algorithm.dart';
import '../../enum/rsa_key_size.dart';
import '../../type/signing_key_material.dart';
import 'rsa_public_material.dart';

/// RSA secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RSASecretMaterial implements SigningKeyMaterialInterface {
  static const publicExponent = 65537;
  static const mrTests = 64;

  /// RSA secret exponent d
  final BigInt exponent;

  /// RSA secret prime value p
  final BigInt primeP;

  /// RSA secret prime value q (p < q)
  final BigInt primeQ;

  /// The multiplicative inverse of p, mod q
  final BigInt coefficient;

  /// RSA private key
  final RSAPrivateKey privateKey;

  @override
  final RSAPublicMaterial publicMaterial;

  RSASecretMaterial(
    this.exponent,
    this.primeP,
    this.primeQ,
    this.publicMaterial, {
    BigInt? coefficient,
  })  : coefficient = coefficient ?? primeP.modInverse(primeQ),
        privateKey = RSAPrivateKey(
          primeP * primeQ,
          exponent,
          primeP,
          primeQ,
        );

  /// Read key material from bytes
  factory RSASecretMaterial.fromBytes(
    final Uint8List bytes,
    final RSAPublicMaterial publicMaterial,
  ) {
    final exponent = Helper.readMPI(bytes);

    var pos = exponent.byteLength + 2;
    final primeP = Helper.readMPI(bytes.sublist(pos));

    pos += primeP.byteLength + 2;
    final primeQ = Helper.readMPI(bytes.sublist(pos));

    pos += primeQ.byteLength + 2;
    final coefficient = Helper.readMPI(bytes.sublist(pos));

    return RSASecretMaterial(
      exponent,
      primeP,
      primeQ,
      publicMaterial,
      coefficient: coefficient,
    );
  }

  factory RSASecretMaterial.generate([
    final RSAKeySize keySize = RSAKeySize.normal,
  ]) {
    final keyGen = KeyGenerator('RSA')
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(
            BigInt.from(publicExponent),
            keySize.bits,
            mrTests,
          ),
          Helper.secureRandom(),
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    final publicKey = keyPair.publicKey as RSAPublicKey;
    final privateKey = keyPair.privateKey as RSAPrivateKey;

    return RSASecretMaterial(
      privateKey.privateExponent!,
      privateKey.p!,
      privateKey.q!,
      RSAPublicMaterial(
        publicKey.modulus!,
        publicKey.publicExponent!,
      ),
    );
  }

  @override
  bool get isValid {
    // expect pq = n
    if ((primeP * primeQ).compareTo(publicMaterial.exponent) != 0) {
      return false;
    }
    // expect p*u = 1 mod q
    if (((primeP * coefficient) % primeQ).compareTo(BigInt.one) != 0) {
      return false;
    }

    final sizeOver3 = (privateKey.modulus!.bitLength / 3).floor();
    final r = Helper.randomBigInt(BigInt.two, BigInt.two << sizeOver3);
    final rde = r * exponent * publicMaterial.exponent;
    return (rde % (primeP - BigInt.one)).compareTo(r) == 0 && (rde % (primeQ - BigInt.one)).compareTo(r) == 0;
  }

  @override
  int get keyLength => publicMaterial.keyLength;

  @override
  Uint8List sign(final Uint8List message, final HashAlgorithm hash) {
    final signer = Signer('${hash.digestName}/RSA')
      ..init(
        true,
        PrivateKeyParameter<RSAPrivateKey>(privateKey),
      );
    final signature = signer.generateSignature(message) as RSASignature;
    return Uint8List.fromList([
      ...(signature.bytes.lengthInBytes * 8).pack16(),
      ...signature.bytes,
    ]);
  }

  @override
  Uint8List get toBytes => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
        ...primeP.bitLength.pack16(),
        ...primeP.toUnsignedBytes(),
        ...primeQ.bitLength.pack16(),
        ...primeQ.toUnsignedBytes(),
        ...coefficient.bitLength.pack16(),
        ...coefficient.toUnsignedBytes(),
      ]);
}
