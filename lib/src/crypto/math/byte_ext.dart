// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

extension Uint8ListExt on Uint8List {
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
