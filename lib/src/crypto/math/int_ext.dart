// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
extension IntExt on int {
  Uint8List pack16([Endian endian = Endian.big]) => Uint8List(2)
    ..buffer.asByteData().setInt16(
          0,
          this,
          endian,
        );

  Uint8List pack16Le() => pack16(Endian.little);

  Uint8List pack32([Endian endian = Endian.big]) => Uint8List(4)
    ..buffer.asByteData().setInt32(
          0,
          this,
          endian,
        );

  Uint8List pack32Le() => pack32(Endian.little);

  Uint8List pack64([Endian endian = Endian.big]) => Uint8List(8)
    ..buffer.asByteData().setInt64(
          0,
          this,
          endian,
        );

  Uint8List pack64Le() => pack64(Endian.little);

  int rotateLeft8(int n) {
    assert(n >= 0);
    assert((this >= 0) && (this <= 0xff));
    n &= 0x07;
    return ((this << n) & 0xff) | (this >> (8 - n));
  }

  int shiftLeft32(final int n) {
    return (Int64(toUnsigned(32)) << n).toInt();
  }

  int shiftRight32(final int n) {
    return (Int64(toUnsigned(32)) >> n).toInt();
  }

  int rotateLeft32(final int n) {
    final num = Int64(toUnsigned(32));
    return ((num << n) + (num >> (32 - n))).toInt();
  }

  int rotateRight32(final int n) {
    final num = Int64(toUnsigned(32));
    return ((num >> n) + (num << (32 - n))).toInt();
  }
}
