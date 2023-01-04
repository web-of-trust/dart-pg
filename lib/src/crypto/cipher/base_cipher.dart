/// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

/// Base implementation of [BlockCipher] which provides shared methods.
abstract class BaseCipher implements BlockCipher {
  static const _mask32 = 0xFFFFFFFF;

  @override
  Uint8List process(final Uint8List data) {
    final out = Uint8List(blockSize);
    final len = processBlock(data, 0, out, 0);
    return out.sublist(0, len);
  }

  static int intRotateLeft(int i, int distance) {
    return (i << distance) ^ (i >> -distance);
  }

  static int intRotateRight(int i, int distance) {
    return (i >> distance) ^ (i << -distance);
  }

  static void pack32(int x, dynamic out, int offset, Endian endian) {
    assert((x >= 0) && (x <= _mask32));
    if (out is! ByteData) {
      out = ByteData.view(out.buffer as ByteBuffer, out.offsetInBytes, out.length);
    }
    out.setUint32(offset, x, endian);
  }

  static int unpack32(dynamic inp, int offset, Endian endian) {
    if (inp is! ByteData) {
      inp = ByteData.view(inp.buffer, inp.offsetInBytes, inp.length);
    }
    return inp.getUint32(offset, endian);
  }
}
