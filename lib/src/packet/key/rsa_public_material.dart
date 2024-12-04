/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/verification_key_material.dart';

/// RSA public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RSAPublicMaterial implements VerificationKeyMaterial {
  /// RSA modulus n
  final BigInt modulus;

  /// RSA public encryption exponent e
  final BigInt exponent;

  /// RSA public key
  final RSAPublicKey publicKey;

  RSAPublicMaterial(this.modulus, this.exponent)
      : publicKey = RSAPublicKey(
          modulus,
          exponent,
        );

  factory RSAPublicMaterial.fromBytes(final Uint8List bytes) {
    final modulus = Helper.readMPI(bytes);
    return RSAPublicMaterial(
      modulus,
      Helper.readMPI(bytes.sublist(modulus.byteLength + 2)),
    );
  }

  @override
  get keyStrength => modulus.bitLength;

  @override
  get toBytes => Uint8List.fromList([
        ...modulus.bitLength.pack16(),
        ...modulus.toUnsignedBytes(),
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  @override
  verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final signer = Signer('${hash.digestName}/RSA')
      ..init(
        false,
        PublicKeyParameter<RSAPublicKey>(publicKey),
      );
    return signer.verifySignature(
      message,
      RSASignature(Helper.readMPI(signature).toUnsignedBytes()),
    );
  }
}
