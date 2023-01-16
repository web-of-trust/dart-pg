// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

const _mask3 = 0x07;
const _mask5 = 0x1f;
// const _mask6 = 0x3f;
const _mask8 = 0xff;
// const _mask16 = 0xffff;
const _mask32 = 0xffffffff;

const _mask32HiBits = [
  0xffffffff,
  0x7fffffff,
  0x3fffffff,
  0x1fffffff,
  0x0fffffff,
  0x07ffffff,
  0x03ffffff,
  0x01ffffff,
  0x00ffffff,
  0x007fffff,
  0x003fffff,
  0x001fffff,
  0x000fffff,
  0x0007ffff,
  0x0003ffff,
  0x0001ffff,
  0x0000ffff,
  0x00007fff,
  0x00003fff,
  0x00001fff,
  0x00000fff,
  0x000007ff,
  0x000003ff,
  0x000001ff,
  0x000000ff,
  0x0000007f,
  0x0000003f,
  0x0000001f,
  0x0000000f,
  0x00000007,
  0x00000003,
  0x00000001,
  0x00000000
];

extension StringHelper on String {
  List<String> chunk(final int chunkSize) {
    assert(chunkSize > 0);
    final chunkCount = (length / chunkSize).ceil();
    return List<String>.generate(chunkCount, (index) {
      final sliceStart = index * chunkSize;
      final sliceEnd = sliceStart + chunkSize;
      return substring(
        sliceStart,
        (sliceEnd < length) ? sliceEnd : length,
      );
    });
  }

  Uint8List hexToBytes() {
    final hex = replaceAll(RegExp(r'\s'), '');
    final result = Uint8List(hex.length ~/ 2);

    for (var i = 0; i < hex.length; i += 2) {
      final num = hex.substring(i, i + 2);
      final byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }

    return result;
  }

  bool hasMatch(final String text) => RegExp(this).hasMatch(text);
}

extension IntHelper on int {
  Uint8List pack16() => Uint8List(2)..buffer.asByteData().setInt16(0, this);

  Uint8List pack16Le() => Uint8List(2)..buffer.asByteData().setInt16(0, this, Endian.little);

  Uint8List pack32() => Uint8List(4)..buffer.asByteData().setInt32(0, this);

  Uint8List pack32Le() => Uint8List(4)..buffer.asByteData().setInt32(0, this, Endian.little);

  Uint8List pack64() => Uint8List(8)..buffer.asByteData().setInt64(0, this);

  Uint8List pack64Le() => Uint8List(8)..buffer.asByteData().setInt64(0, this, Endian.little);

  int rotateLeft8(int n) {
    assert(n >= 0);
    assert((this >= 0) && (this <= _mask8));
    n &= _mask3;
    return ((this << n) & _mask8) | (this >> (8 - n));
  }

  int shiftLeft32(int n) {
    assert((this >= 0) && (this <= _mask32));
    n &= _mask5;
    final num = this & _mask32HiBits[n];
    return ((num << n) & _mask32);
  }

  int rotateLeft32(int n) {
    assert(n >= 0);
    assert((this >= 0) && (this <= _mask32));
    n &= _mask5;
    return shiftLeft32(n) | (this >> (32 - n));
  }

  int rotateRight32(int n) {
    assert(n >= 0);
    assert((this >= 0) && (this <= _mask32));
    n &= _mask5;
    return (this >> n) | shiftLeft32(32 - n);
  }
}

extension Uint8ListHelper on Uint8List {
  int toIn16() => buffer.asByteData().getInt16(0);

  int toUint16() => buffer.asByteData().getUint16(0);

  int toLeIn16() => buffer.asByteData().getInt16(0, Endian.little);

  int toLeUint16() => buffer.asByteData().getUint16(0, Endian.little);

  int toInt32() => buffer.asByteData().getInt32(0);

  int toUint32() => buffer.asByteData().getUint32(0);

  int toLeInt32() => buffer.asByteData().getInt32(0, Endian.little);

  int toLeUint32() => buffer.asByteData().getUint32(0, Endian.little);

  int toInt64() => buffer.asByteData().getInt64(0);

  int toUint64() => buffer.asByteData().getUint64(0);

  int toLeInt64() => buffer.asByteData().getInt64(0, Endian.little);

  int toLeUint64() => buffer.asByteData().getUint64(0, Endian.little);

  BigInt toBigInt() {
    final negative = isNotEmpty && this[0] & 0x80 == 0x80;
    BigInt result;
    if (length == 1) {
      result = BigInt.from(this[0]);
    } else {
      result = BigInt.zero;
      for (var i = 0; i < length; i++) {
        final item = this[length - i - 1];
        result |= (BigInt.from(item) << (8 * i));
      }
    }
    return result != BigInt.zero
        ? negative
            ? result.toSigned(result.bitLength)
            : result
        : BigInt.zero;
  }

  BigInt toBigIntWithSign(int sign) {
    if (sign == 0) {
      return BigInt.zero;
    }

    BigInt result;

    if (length == 1) {
      result = BigInt.from(this[0]);
    } else {
      result = BigInt.from(0);
      for (var i = 0; i < length; i++) {
        var item = this[length - i - 1];
        result |= (BigInt.from(item) << (8 * i));
      }
    }

    if (result != BigInt.zero) {
      if (sign < 0) {
        result = result.toSigned(result.bitLength);
      } else {
        result = result.toUnsigned(result.bitLength);
      }
    }
    return result;
  }

  DateTime toDateTime() => DateTime.fromMillisecondsSinceEpoch(toInt32() * 1000);

  String toHexadecimal() {
    final result = StringBuffer();
    for (var i = 0; i < lengthInBytes; i++) {
      final part = this[i];
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }

  bool equals(final Uint8List expected) {
    if (expected == this) {
      return true;
    }

    final len = (expected.length < length) ? expected.length : length;
    var nonEqual = expected.length ^ length;

    for (var i = 0; i != len; i++) {
      nonEqual |= (expected[i] ^ this[i]);
    }
    for (var i = len; i < length; i++) {
      nonEqual |= (this[i] ^ ~this[i]);
    }

    return nonEqual == 0;
  }
}

extension BigIntHelper on BigInt {
  Uint8List toBytes() {
    if (this == BigInt.zero) {
      return Uint8List.fromList([0]);
    }

    final byteMask = BigInt.from(0xff);
    final negativeFlag = BigInt.from(0x80);

    final int needsPaddingByte;
    final int rawSize;

    if (this > BigInt.zero) {
      rawSize = (bitLength + 7) >> 3;
      needsPaddingByte = ((this >> (rawSize - 1) * 8) & negativeFlag) == negativeFlag ? 1 : 0;
    } else {
      needsPaddingByte = 0;
      rawSize = (bitLength + 8) >> 3;
    }

    final size = rawSize + needsPaddingByte;
    final result = Uint8List(size);
    var number = this;
    for (var i = 0; i < rawSize; i++) {
      result[size - i - 1] = (number & byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  Uint8List toUnsignedBytes() {
    if (this == BigInt.zero) {
      return Uint8List.fromList([0]);
    }
    final byteMask = BigInt.from(0xff);
    final size = bitLength + (isNegative ? 8 : 7) >> 3;
    var result = Uint8List(size);
    var number = this;
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }
}

extension DateTimeHelper on DateTime {
  Uint8List toBytes() => (millisecondsSinceEpoch ~/ 1000).pack32();
}
