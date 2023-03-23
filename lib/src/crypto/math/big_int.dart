// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

extension BigIntExt on BigInt {
  int get byteLength => (bitLength + 7) >> 3;

  Uint8List toBytes() {
    if (sign == 0) {
      return Uint8List.fromList([0]);
    }

    final byteMask = BigInt.from(0xff);
    final negativeFlag = BigInt.from(0x80);

    final int needsPaddingByte;
    final int rawSize;

    if (sign > 0) {
      rawSize = (bitLength + 7) >> 3;
      needsPaddingByte =
          ((this >> (rawSize - 1) * 8) & negativeFlag) == negativeFlag ? 1 : 0;
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
    if (sign == 0) {
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
        if ((m % _lowprimes[i++]).sign == 0) {
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
    if (x.sign == 0) return -1;
    var r = 0;
    while ((x & BigInt.from(0xffffffff)).sign == 0) {
      x >>= 32;
      r += 32;
    }
    if ((x & BigInt.from(0xffff)).sign == 0) {
      x >>= 16;
      r += 16;
    }
    if ((x & BigInt.from(0xff)).sign == 0) {
      x >>= 8;
      r += 8;
    }
    if ((x & BigInt.from(0xf)).sign == 0) {
      x >>= 4;
      r += 4;
    }
    if ((x & BigInt.from(3)).sign == 0) {
      x >>= 2;
      r += 2;
    }
    if ((x & BigInt.one).sign == 0) ++r;
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
