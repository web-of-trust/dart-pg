// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../crypto/signer/dsa.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class DSASecretParams extends KeyParams {
  /// DSA secret exponent x
  final BigInt secretExponent;

  DSASecretParams(this.secretExponent);

  factory DSASecretParams.fromByteData(final Uint8List bytes) => DSASecretParams(Helper.readMPI(bytes));

  @override
  Uint8List encode() => Uint8List.fromList([
        ...secretExponent.bitLength.pack16(),
        ...secretExponent.toUnsignedBytes(),
      ]);

  Future<Uint8List> sign(
    final DSAPublicParams publicParams,
    final Uint8List message,
    final HashAlgorithm hash,
  ) async {
    final signer = DSASigner(Digest(hash.digestName))
      ..init(
        true,
        PrivateKeyParameter<DSAPrivateKey>(DSAPrivateKey(
          secretExponent,
          publicParams.prime,
          publicParams.order,
          publicParams.generator,
        )),
      );
    return signer.generateSignature(message).encode();
  }
}
