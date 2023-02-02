// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'key_params.dart';

class RSAPublicParams extends KeyParams {
  final RSAPublicKey publicKey;

  RSAPublicParams(this.publicKey);

  factory RSAPublicParams.fromPacketData(Uint8List bytes) {
    final modulus = KeyParams.readMPI(bytes);
    final publicExponent = KeyParams.readMPI(bytes.sublist(modulus.byteLength + 2));

    return RSAPublicParams(RSAPublicKey(modulus, publicExponent));
  }

  /// RSA public modulus n
  BigInt? get modulus => publicKey.modulus;

  /// RSA public encryption exponent e
  BigInt? get publicExponent => publicKey.publicExponent;

  @override
  Uint8List encode() => Uint8List.fromList([
        ...modulus!.bitLength.pack16(),
        ...modulus!.toUnsignedBytes(),
        ...publicExponent!.bitLength.pack16(),
        ...publicExponent!.toUnsignedBytes(),
      ]);
}
