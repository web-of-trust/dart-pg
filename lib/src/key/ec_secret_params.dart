// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'key_params.dart';

class ECSecretParams extends KeyParams {
  final ECPrivateKey privateKey;

  ECSecretParams(this.privateKey);

  factory ECSecretParams.fromPacketData(Uint8List bytes) {
    return ECSecretParams(ECPrivateKey(KeyParams.readMPI(bytes), null));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(privateKey.d!.bitLength.pack16());
    bytes.addAll(privateKey.d!.toUnsignedBytes());

    return Uint8List.fromList(bytes);
  }
}
