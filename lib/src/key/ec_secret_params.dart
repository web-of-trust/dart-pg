// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';
import 'key_params.dart';

class ECSecretParams extends KeyParams {
  /// ECC's d private parameter
  final BigInt d;

  ECSecretParams(this.d);

  factory ECSecretParams.fromPacketData(Uint8List bytes) {
    return ECSecretParams(KeyParams.readMPI(bytes));
  }

  @override
  Uint8List encode() => Uint8List.fromList([...d.bitLength.pack16(), ...d.toUnsignedBytes()]);
}
