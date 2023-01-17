// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:math';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/api.dart';

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
  Uint8List pack16([Endian endian = Endian.big]) => Uint8List(2)..buffer.asByteData().setInt16(0, this, endian);

  Uint8List pack16Le() => pack16(Endian.little);

  Uint8List pack32([Endian endian = Endian.big]) => Uint8List(4)..buffer.asByteData().setInt32(0, this, endian);

  Uint8List pack32Le() => pack32(Endian.little);

  Uint8List pack64([Endian endian = Endian.big]) => Uint8List(8)..buffer.asByteData().setInt64(0, this, endian);

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

extension Uint8ListHelper on Uint8List {
  int toIn16([Endian endian = Endian.big]) => buffer.asByteData().getInt16(0, endian);

  int toUint16([Endian endian = Endian.big]) => buffer.asByteData().getUint16(0, endian);

  int toLeIn16() => toIn16(Endian.little);

  int toLeUint16() => toUint16(Endian.little);

  int toInt32([Endian endian = Endian.big]) => buffer.asByteData().getInt32(0, endian);

  int toUint32([Endian endian = Endian.big]) => buffer.asByteData().getUint32(0, endian);

  int toLeInt32() => toInt32(Endian.little);

  int toLeUint32() => toUint32(Endian.little);

  int toInt64([Endian endian = Endian.big]) => buffer.asByteData().getInt64(0, endian);

  int toUint64([Endian endian = Endian.big]) => buffer.asByteData().getUint64(0, endian);

  int toLeInt64() => toInt64(Endian.little);

  int toLeUint64() => toUint64(Endian.little);

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

  BigInt toBigIntWithSign(final int sign) {
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

SecureRandom newSecureRandom() {
  final random = Random.secure();
  return SecureRandom('Fortuna')
    ..seed(KeyParameter(Uint8List.fromList(List.generate(32, ((_) => random.nextInt(0xffffffff))))));
}
