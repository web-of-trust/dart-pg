// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pinenacl/ed25519.dart';

import '../../crypto/math/big_int.dart';
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

  Uint8List sign(
    final Uint8List message,
    final HashAlgorithm hash,
  ) {
    final signingKey = SigningKey.fromSeed(seed.toUnsignedBytes());
    final signed = signingKey.sign(Helper.hashDigest(message, hash));
    final r = signed.signature.asTypedList.sublist(0, 32);
    final s = signed.signature.asTypedList.sublist(32);
    return Uint8List.fromList([
      ...(r.lengthInBytes * 8).pack16(),
      ...r,
      ...(r.lengthInBytes * 8).pack16(),
      ...s,
    ]);
  }
}
