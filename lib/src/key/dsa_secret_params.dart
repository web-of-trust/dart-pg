// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';
import 'key_params.dart';

class DSASecretParams extends KeyParams {
  final BigInt x;

  DSASecretParams(this.x);

  factory DSASecretParams.fromPacketData(Uint8List bytes) {
    return DSASecretParams(KeyParams.readMPI(bytes));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(x.bitLength.pack16());
    bytes.addAll(x.toUnsignedBytes());

    return Uint8List.fromList(bytes);
  }
}
