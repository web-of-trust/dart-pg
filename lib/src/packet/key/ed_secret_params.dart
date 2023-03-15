// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
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
}
