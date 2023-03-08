// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class RSAPublicParams extends KeyParams {
  /// RSA modulus n
  final BigInt modulus;

  /// RSA public encryption exponent e
  final BigInt publicExponent;

  final RSAPublicKey publicKey;

  RSAPublicParams(this.modulus, this.publicExponent) : publicKey = RSAPublicKey(modulus, publicExponent);

  factory RSAPublicParams.fromPacketData(final Uint8List bytes) {
    final modulus = Helper.readMPI(bytes);
    final publicExponent = Helper.readMPI(bytes.sublist(modulus.byteLength + 2));

    return RSAPublicParams(modulus, publicExponent);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...modulus.bitLength.pack16(),
        ...modulus.toUnsignedBytes(),
        ...publicExponent.bitLength.pack16(),
        ...publicExponent.toUnsignedBytes(),
      ]);

  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final signer = Signer('${hash.digestName}/RSA')..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
    return signer.verifySignature(message, RSASignature(Helper.readMPI(signature).toUnsignedBytes()));
  }
}
