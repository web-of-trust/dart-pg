// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

final _byteMask = BigInt.from(0xff);
final _negativeFlag = BigInt.from(0x80);

class ByteUtils {
  static Uint8List int16Bytes(int number) => Uint8List(2)..buffer.asByteData().setInt16(0, number);

  static int bytesToIn16(Uint8List bytes) => (bytes[0] << 8) | bytes[1];

  static Uint8List int32Bytes(int number) => Uint8List(4)..buffer.asByteData().setUint32(0, number);

  static int bytesToIn32(Uint8List bytes) => (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];

  static int littleEndianToIn32(Uint8List bytes) => (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];

  static Uint8List int32ToLittleEndian(int number) {
    return Uint8List.fromList([number & 0x00, (number >>> 8) & 0x00, (number >>> 16) & 0x00, (number >>> 24) & 0x00]);
  }

  static Uint8List int64Bytes(int number) => Uint8List(8)..buffer.asByteData().setUint64(0, number);

  static int bytesToInt64(Uint8List bytes) =>
      (bytes[0] << 56) |
      (bytes[1] << 48) |
      (bytes[2] << 40) |
      (bytes[3] << 32) |
      (bytes[4] << 24) |
      (bytes[5] << 16) |
      (bytes[6] << 8) |
      bytes[7];

  static Uint8List timeToBytes(DateTime time) {
    return int32Bytes(time.millisecondsSinceEpoch ~/ 1000);
  }

  static DateTime bytesToTime(Uint8List bytes) => DateTime.fromMillisecondsSinceEpoch(bytesToIn32(bytes) * 1000);

  static Uint8List bigIntBytes(BigInt? number) {
    if (number == BigInt.zero) {
      return Uint8List.fromList([0]);
    }

    final int needsPaddingByte;
    final int rawSize;

    if (number! > BigInt.zero) {
      rawSize = (number.bitLength + 7) >> 3;
      needsPaddingByte = ((number >> (rawSize - 1) * 8) & _negativeFlag) == _negativeFlag ? 1 : 0;
    } else {
      needsPaddingByte = 0;
      rawSize = (number.bitLength + 8) >> 3;
    }

    final size = rawSize + needsPaddingByte;
    final result = Uint8List(size);
    for (var i = 0; i < rawSize; i++) {
      result[size - i - 1] = (number! & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  static BigInt bytesToBigInt(Uint8List bytes) {
    final negative = bytes.isNotEmpty && bytes[0] & 0x80 == 0x80;
    BigInt result;
    if (bytes.length == 1) {
      result = BigInt.from(bytes[0]);
    } else {
      result = BigInt.zero;
      for (var i = 0; i < bytes.length; i++) {
        final item = bytes[bytes.length - i - 1];
        result |= (BigInt.from(item) << (8 * i));
      }
    }
    return result != BigInt.zero
        ? negative
            ? result.toSigned(result.bitLength)
            : result
        : BigInt.zero;
  }

  static bool equalsUint8List(Uint8List expected, Uint8List supplied) {
    if (expected == supplied) {
      return true;
    }

    int len = (expected.length < supplied.length) ? expected.length : supplied.length;

    int nonEqual = expected.length ^ supplied.length;

    for (int i = 0; i != len; i++) {
      nonEqual |= (expected[i] ^ supplied[i]);
    }
    for (int i = len; i < supplied.length; i++) {
      nonEqual |= (supplied[i] ^ ~supplied[i]);
    }

    return nonEqual == 0;
  }
}
