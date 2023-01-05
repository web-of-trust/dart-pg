// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

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
  Uint8List to16Bytes() => Uint8List(2)..buffer.asByteData().setInt16(0, this);

  Uint8List to32Bytes() => Uint8List(4)..buffer.asByteData().setInt32(0, this);

  Uint8List to64Bytes() => Uint8List(8)..buffer.asByteData().setUint64(0, this);

  Uint8List toLeBytes() =>
      Uint8List.fromList([this & 0x00, (this >>> 8) & 0x00, (this >>> 16) & 0x00, (this >>> 24) & 0x00]);

  int rotateLeft(final int distance) => (this << distance) ^ (this >>> -distance);

  int rotateRight(final int distance) => (this >> distance) ^ (this << -distance);
}

extension Uint8ListHelper on Uint8List {
  int toIn16() => (this[0] << 8) | this[1];

  int toIn32() => (this[0] << 24) | (this[1] << 16) | (this[2] << 8) | this[3];

  int toInt64() =>
      (this[0] << 56) |
      (this[1] << 48) |
      (this[2] << 40) |
      (this[3] << 32) |
      (this[4] << 24) |
      (this[5] << 16) |
      (this[6] << 8) |
      this[7];

  int toLeInt32() => (this[3] << 24) | (this[2] << 16) | (this[1] << 8) | this[0];

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

  DateTime toDateTime() => DateTime.fromMillisecondsSinceEpoch(toIn32() * 1000);

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
}

extension DateTimeHelper on DateTime {
  Uint8List toBytes() => (millisecondsSinceEpoch ~/ 1000).to32Bytes();
}

class Pack {
  static const _mask32 = 0xFFFFFFFF;

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
