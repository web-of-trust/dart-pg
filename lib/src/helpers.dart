// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/api.dart' as pc;

import 'enum/hash_algorithm.dart';
import 'enum/symmetric_algorithm.dart';
import 'openpgp.dart';

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

  Uint8List stringToBytes() => utf8.encoder.convert(this);

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
  int get byteLength => (bitLength + 7) >> 3;

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

  /// test primality with certainty >= 1-.5^t
  bool isProbablePrime(final int t) {
    final x = abs();
    if (this <= _lowprimes.last) {
      for (var i = 0; i < _lowprimes.length; ++i) {
        if (this == _lowprimes[i]) return true;
      }
      return false;
    }
    if (x.isEven) return false;
    var i = 1;
    while (i < _lowprimes.length) {
      var m = _lowprimes[i], j = i + 1;
      while (j < _lowprimes.length && m < _lplim) {
        m *= _lowprimes[j++];
      }
      m = x % m;
      while (i < j) {
        if (m % _lowprimes[i++] == BigInt.zero) {
          return false;
        }
      }
    }
    return x._millerRabin(t);
  }

  int get nafWeight {
    if (sign == 0) {
      return 0;
    }
    return (((this << 1) + this) ^ this).bitLength;
  }

  /// true if probably prime (HAC 4.24, Miller-Rabin)
  bool _millerRabin(int t) {
    // Implementation borrowed from bignum.BigIntegerDartvm.
    final n1 = this - BigInt.one;
    final k = n1._lbit();
    if (k <= 0) return false;
    final r = n1 >> k;
    t = (t + 1) >> 1;
    if (t > _lowprimes.length) t = _lowprimes.length;
    BigInt a;
    for (var i = 0; i < t; ++i) {
      a = _lowprimes[i];
      var y = a.modPow(r, this);
      if (y.compareTo(BigInt.one) != 0 && y.compareTo(n1) != 0) {
        var j = 1;
        while (j++ < k && y.compareTo(n1) != 0) {
          y = y.modPow(BigInt.two, this);
          if (y.compareTo(BigInt.one) == 0) return false;
        }
        if (y.compareTo(n1) != 0) return false;
      }
    }
    return true;
  }

  /// return index of lowest 1-bit in x, x < 2^31
  int _lbit() {
    var x = this;
    if (x == BigInt.zero) return -1;
    var r = 0;
    while ((x & BigInt.from(0xffffffff)) == BigInt.zero) {
      x >>= 32;
      r += 32;
    }
    if ((x & BigInt.from(0xffff)) == BigInt.zero) {
      x >>= 16;
      r += 16;
    }
    if ((x & BigInt.from(0xff)) == BigInt.zero) {
      x >>= 8;
      r += 8;
    }
    if ((x & BigInt.from(0xf)) == BigInt.zero) {
      x >>= 4;
      r += 4;
    }
    if ((x & BigInt.from(3)) == BigInt.zero) {
      x >>= 2;
      r += 2;
    }
    if ((x & BigInt.one) == BigInt.zero) ++r;
    return r;
  }

  static final List<BigInt> _lowprimes = [
    BigInt.from(2),
    BigInt.from(3),
    BigInt.from(5),
    BigInt.from(7),
    BigInt.from(11),
    BigInt.from(13),
    BigInt.from(17),
    BigInt.from(19),
    BigInt.from(23),
    BigInt.from(29),
    BigInt.from(31),
    BigInt.from(37),
    BigInt.from(41),
    BigInt.from(43),
    BigInt.from(47),
    BigInt.from(53),
    BigInt.from(59),
    BigInt.from(61),
    BigInt.from(67),
    BigInt.from(71),
    BigInt.from(73),
    BigInt.from(79),
    BigInt.from(83),
    BigInt.from(89),
    BigInt.from(97),
    BigInt.from(101),
    BigInt.from(103),
    BigInt.from(107),
    BigInt.from(109),
    BigInt.from(113),
    BigInt.from(127),
    BigInt.from(131),
    BigInt.from(137),
    BigInt.from(139),
    BigInt.from(149),
    BigInt.from(151),
    BigInt.from(157),
    BigInt.from(163),
    BigInt.from(167),
    BigInt.from(173),
    BigInt.from(179),
    BigInt.from(181),
    BigInt.from(191),
    BigInt.from(193),
    BigInt.from(197),
    BigInt.from(199),
    BigInt.from(211),
    BigInt.from(223),
    BigInt.from(227),
    BigInt.from(229),
    BigInt.from(233),
    BigInt.from(239),
    BigInt.from(241),
    BigInt.from(251),
    BigInt.from(257),
    BigInt.from(263),
    BigInt.from(269),
    BigInt.from(271),
    BigInt.from(277),
    BigInt.from(281),
    BigInt.from(283),
    BigInt.from(293),
    BigInt.from(307),
    BigInt.from(311),
    BigInt.from(313),
    BigInt.from(317),
    BigInt.from(331),
    BigInt.from(337),
    BigInt.from(347),
    BigInt.from(349),
    BigInt.from(353),
    BigInt.from(359),
    BigInt.from(367),
    BigInt.from(373),
    BigInt.from(379),
    BigInt.from(383),
    BigInt.from(389),
    BigInt.from(397),
    BigInt.from(401),
    BigInt.from(409),
    BigInt.from(419),
    BigInt.from(421),
    BigInt.from(431),
    BigInt.from(433),
    BigInt.from(439),
    BigInt.from(443),
    BigInt.from(449),
    BigInt.from(457),
    BigInt.from(461),
    BigInt.from(463),
    BigInt.from(467),
    BigInt.from(479),
    BigInt.from(487),
    BigInt.from(491),
    BigInt.from(499),
    BigInt.from(503),
    BigInt.from(509)
  ];

  static final BigInt _lplim = (BigInt.one << 26) ~/ _lowprimes.last;
}

extension DateTimeHelper on DateTime {
  Uint8List toBytes() => (millisecondsSinceEpoch ~/ 1000).pack32();
}

class Helper {
  static final _random = Random.secure();

  static final _secureRandom = pc.SecureRandom('Fortuna')
    ..seed(pc.KeyParameter(Uint8List.fromList(List.generate(32, ((_) => _random.nextInt(0xffffffff))))));

  static BigInt readMPI(Uint8List bytes) {
    final bitLength = bytes.sublist(0, 2).toUint16();
    return bytes.sublist(2, ((bitLength + 7) >> 3) + 2).toBigIntWithSign(1);
  }

  static pc.SecureRandom secureRandom() => _secureRandom;

  static Uint8List generatePrefix([final SymmetricAlgorithm symmetric = OpenPGP.preferredSymmetric]) {
    final prefix = _secureRandom.nextBytes(symmetric.blockSize);
    final repeat = [prefix[prefix.length - 2], prefix[prefix.length - 1]];
    return Uint8List.fromList([...prefix, ...repeat]);
  }

  static Uint8List generateEncryptionKey([final SymmetricAlgorithm symmetric = OpenPGP.preferredSymmetric]) =>
      _secureRandom.nextBytes((symmetric.keySize + 7) >> 3);

  static Uint8List hashDigest(final Uint8List input, [HashAlgorithm hash = HashAlgorithm.sha256]) {
    switch (hash) {
      case HashAlgorithm.sha1:
        return Uint8List.fromList(sha1.convert(input).bytes);
      case HashAlgorithm.ripemd160:
        final digest = pc.Digest('RIPEMD-160');
        return digest.process(input);
      case HashAlgorithm.sha256:
        return Uint8List.fromList(sha256.convert(input).bytes);
      case HashAlgorithm.sha384:
        return Uint8List.fromList(sha384.convert(input).bytes);
      case HashAlgorithm.sha512:
        return Uint8List.fromList(sha512.convert(input).bytes);
      case HashAlgorithm.sha224:
        return Uint8List.fromList(sha224.convert(input).bytes);
      default:
        throw UnsupportedError('Digest type not supported.');
    }
  }

  /// Calculates a 16bit sum of a Uint8List by adding each character codes modulus 65535
  static Uint8List calculateChecksum(final Uint8List data) {
    var s = 0;
    for (var i = 0; i < data.lengthInBytes; i++) {
      s = (s + data[i]) & 0xffff;
    }
    return s.pack16();
  }

  /// Create a EME-PKCS1-v1_5 padded message
  static Uint8List emeEncode(final Uint8List message, final int keyLength) {
    final mLength = message.length;
    // length checking
    if (mLength > keyLength - 11) {
      throw StateError('Message too long');
    }
    final ps = _getPKCS1Padding(keyLength - mLength - 3);
    final encoded = Uint8List(keyLength);
    encoded[1] = 2;
    encoded.setAll(2, ps);
    encoded.setAll(keyLength - mLength, message);
    return encoded;
  }

  /// Decode a EME-PKCS1-v1_5 padded message
  static emeDecode(final Uint8List encoded) {
    var offset = 2;
    var separatorNotFound = 1;
    for (var j = offset; j < encoded.length; j++) {
      separatorNotFound &= (encoded[j] != 0) ? 1 : 0;
      offset += separatorNotFound;
    }
    return encoded.sublist(offset + 1);
  }

  static BigInt randomBigIntInRange(final BigInt min, final BigInt max, {pc.SecureRandom? random}) {
    random = random ?? secureRandom();
    BigInt k;
    do {
      k = random.nextBigInteger(max.bitLength);
    } while (k.compareTo(min) <= 0 || k.compareTo(max) >= 0);
    return k;
  }

  static Uint8List _getPKCS1Padding(final int length) {
    final result = Uint8List(length);
    var count = 0;
    while (count < length) {
      final randomBytes = _secureRandom.nextBytes(length - count);
      for (var i = 0; i < randomBytes.length; i++) {
        if (randomBytes[i] != 0) {
          result[count++] = randomBytes[i];
        }
      }
    }
    return result;
  }
}
