// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pinenacl/ed25519.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class EdSecretParams extends KeyParams {
  /// Ed's seed parameter
  final BigInt seed;

  EdSecretParams(this.seed);

  factory EdSecretParams.fromByteData(final Uint8List bytes) => EdSecretParams(Helper.readMPI(bytes));

  @override
  Uint8List encode() => Uint8List.fromList([
        ...seed.bitLength.pack16(),
        ...seed.toUnsignedBytes(),
      ]);

  Future<Uint8List> sign(
    final Uint8List message,
    final HashAlgorithm hash,
  ) async {
    final signed = SigningKey.fromSeed(seed.toUnsignedBytes()).sign(
      Helper.hashDigest(message, hash),
    );
    final bitLength = (SignedMessage.signatureLength * 4).pack16();
    return Uint8List.fromList([
      ...bitLength, // r bit length
      ...signed.signature.sublist(0, SignedMessage.signatureLength ~/ 2), // r
      ...bitLength, // s bit length
      ...signed.signature.sublist(SignedMessage.signatureLength ~/ 2), // s
    ]);
  }

  /// Validate EdDSA parameters
  bool validatePublicParams(EdDSAPublicParams publicParams) {
    final signingKey = SigningKey.fromSeed(seed.toUnsignedBytes());
    final dG = Uint8List.fromList([
      0x40,
      ...signingKey.verifyKey.asTypedList,
    ]);
    return publicParams.q.compareTo(dG.toBigIntWithSign(1)) == 0;
  }
}
