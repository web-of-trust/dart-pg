// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pinenacl/api.dart' as nacl;
import 'package:pointycastle/export.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/curve_info.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class ECSecretParams extends KeyParams {
  /// ECC's d private parameter
  final BigInt d;

  ECSecretParams(this.d);

  factory ECSecretParams.fromByteData(final Uint8List bytes) => ECSecretParams(
        Helper.readMPI(bytes),
      );

  @override
  Uint8List encode() => Uint8List.fromList([
        ...d.bitLength.pack16(),
        ...d.toUnsignedBytes(),
      ]);

  Future<Uint8List> sign(
    final ECPublicParams publicParams,
    final Uint8List message,
    final HashAlgorithm hash,
  ) async {
    final signer = Signer('${hash.digestName}/DET-ECDSA')
      ..init(
        true,
        PrivateKeyParameter<ECPrivateKey>(
          ECPrivateKey(
            d,
            ECDomainParameters(
              publicParams.curve.name.toLowerCase(),
            ),
          ),
        ),
      );
    final signature = signer.generateSignature(message) as ECSignature;
    return Uint8List.fromList([
      ...signature.r.bitLength.pack16(),
      ...signature.r.toUnsignedBytes(),
      ...signature.s.bitLength.pack16(),
      ...signature.s.toUnsignedBytes(),
    ]);
  }

  /// Validate EC parameters
  bool validatePublicParams(final ECPublicParams publicParams) {
    switch (publicParams.curve) {
      case CurveInfo.curve25519:
        final privateKey = nacl.PrivateKey(
          Uint8List.fromList(d.toUnsignedBytes().reversed.toList()),
        );
        final dG = Uint8List.fromList([
          0x40,
          ...privateKey.publicKey.asTypedList,
        ]);
        return publicParams.q.compareTo(dG.toBigIntWithSign(1)) == 0;
      case CurveInfo.ed25519:
        return false;
      default:
        final parameters =
            ECDomainParameters(publicParams.curve.name.toLowerCase());
        final q =
            parameters.curve.decodePoint(publicParams.q.toUnsignedBytes());
        return q != null && !q.isInfinity && (parameters.G * d) == q;
    }
  }
}
