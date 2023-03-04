// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class ECSecretParams extends KeyParams {
  /// ECC's d private parameter
  final BigInt d;

  ECSecretParams(this.d);

  factory ECSecretParams.fromPacketData(final Uint8List bytes) => ECSecretParams(Helper.readMPI(bytes));

  @override
  Uint8List encode() => Uint8List.fromList([...d.bitLength.pack16(), ...d.toUnsignedBytes()]);

  Uint8List sign(
    final ECPublicParams publicParams,
    final Uint8List message,
    final HashAlgorithm hash,
  ) {
    final signer = Signer('${hash.digestName}/DET-ECDSA')
      ..init(true, PrivateKeyParameter<ECPrivateKey>(ECPrivateKey(d, publicParams.publicKey.parameters)));
    final signature = signer.generateSignature(message) as ECSignature;
    return Uint8List.fromList([
      ...signature.r.bitLength.pack16(),
      ...signature.r.toUnsignedBytes(),
      ...signature.s.bitLength.pack16(),
      ...signature.s.toUnsignedBytes(),
    ]);
  }
}
