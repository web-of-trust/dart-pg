// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';

abstract class KeyParams {
  Uint8List encode();

  static BigInt readMPI(Uint8List bytes) {
    final bitLength = bytes.sublist(0, 2).toIn16();
    return bytes.sublist(2, ((bitLength + 7) >> 3) + 2).toBigInt();
  }
}
