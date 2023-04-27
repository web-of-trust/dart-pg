// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class RSAPublicParams implements VerificationParams {
  /// RSA modulus n
  final BigInt modulus;

  /// RSA public encryption exponent e
  final BigInt exponent;

  final RSAPublicKey publicKey;

  RSAPublicParams(this.modulus, this.exponent)
      : publicKey = RSAPublicKey(
          modulus,
          exponent,
        );

  factory RSAPublicParams.fromByteData(final Uint8List bytes) {
    final modulus = Helper.readMPI(bytes);
    return RSAPublicParams(
      modulus,
      Helper.readMPI(bytes.sublist(modulus.byteLength + 2)),
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...modulus.bitLength.pack16(),
        ...modulus.toUnsignedBytes(),
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  @override
  Future<bool> verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) async {
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
