/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

/// Implementation of rfc-7748 x448 field point
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Fp448 {
  /// Field element size
  static const size = 16;

  /// Mask 28 bits
  static const m28 = 0x0fffffff;

  /// Calculate z = x+y mod p.
  static void add(
    final Uint32List x,
    final Uint32List y,
    final Uint32List z,
  ) {
    for (var i = 0; i < size; ++i) {
      z[i] = x[i] + y[i];
    }
  }

  /// Create field element
  static Uint32List create() => Uint32List(size);

  /// Interchange a and b if swap is 1.
  static void cswap(
    final int swap,
    final Uint32List a,
    final Uint32List b,
  ) {
    assert(swap >>> 1 == 0);
    final mask = 0 - swap;
    for (var i = 0; i < size; ++i) {
      final ai = a[i], bi = b[i];
      final dummy = mask & (ai ^ bi);
      a[i] = ai ^ dummy;
      b[i] = bi ^ dummy;
    }
  }

  /// Calculate z = 1/x mod p.
  static void inv(
    final Uint32List x,
    final Uint32List z,
  ) {
    final t = create();
    _powPm3d4(x, t);
    nSqr(t, 2, t);
    mul(t, x, z);
  }

  static void mulA24(
    final Uint32List x,
    final int y,
    final Uint32List z,
  ) {
    final x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
    final x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
    final x8 = x[8], x9 = x[9], x10 = x[10], x11 = x[11];
    final x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];

    var c = x1 * y;
    final z1 = c & m28;
    c >>>= 28;
    var d = x5 * y;
    final z5 = d & m28;
    d >>>= 28;
    var e = x9 * y;
    final z9 = e & m28;
    e >>>= 28;
    var f = x13 * y;
    final z13 = f & m28;
    f >>>= 28;

    c += x2 * y;
    z[2] = c & m28;
    c >>>= 28;
    d += x6 * y;
    z[6] = d & m28;
    d >>>= 28;
    e += x10 * y;
    z[10] = e & m28;
    e >>>= 28;
    f += x14 * y;
    z[14] = f & m28;
    f >>>= 28;

    c += x3 * y;
    z[3] = c & m28;
    c >>>= 28;
    d += x7 * y;
    z[7] = d & m28;
    d >>>= 28;
    e += x11 * y;
    z[11] = e & m28;
    e >>>= 28;
    f += x15 * y;
    z[15] = f & m28;
    f >>>= 28;

    d += f;

    c += x4 * y;
    z[4] = c & m28;
    c >>>= 28;
    d += x8 * y;
    z[8] = d & m28;
    d >>>= 28;
    e += x12 * y;
    z[12] = e & m28;
    e >>>= 28;
    f += x0 * y;
    z[0] = f & m28;
    f >>>= 28;

    z[1] = z1 + f;
    z[5] = z5 + c;
    z[9] = z9 + d;
    z[13] = z13 + e;
  }

  /// Calculate z = x*y mod p.
  static void mul(
    final Uint32List x,
    final Uint32List y,
    final Uint32List z,
  ) {
    final x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
    final x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];

    final u0 = x[8], u1 = x[9], u2 = x[10], u3 = x[11];
    final u4 = x[12], u5 = x[13], u6 = x[14], u7 = x[15];

    final y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3];
    final y4 = y[4], y5 = y[5], y6 = y[6], y7 = y[7];

    final v0 = y[8], v1 = y[9], v2 = y[10], v3 = y[11];
    final v4 = y[12], v5 = y[13], v6 = y[14], v7 = y[15];

    final s0 = x0 + u0;
    final s1 = x1 + u1;
    final s2 = x2 + u2;
    final s3 = x3 + u3;
    final s4 = x4 + u4;
    final s5 = x5 + u5;
    final s6 = x6 + u6;
    final s7 = x7 + u7;

    final t0 = y0 + v0;
    final t1 = y1 + v1;
    final t2 = y2 + v2;
    final t3 = y3 + v3;
    final t4 = y4 + v4;
    final t5 = y5 + v5;
    final t6 = y6 + v6;
    final t7 = y7 + v7;

    final f0 = x0 * y0;
    final f8 = x7 * y1 + x6 * y2 + x5 * y3 + x4 * y4 + x3 * y5 + x2 * y6 + x1 * y7;
    final g0 = u0 * v0;
    final g8 = u7 * v1 + u6 * v2 + u5 * v3 + u4 * v4 + u3 * v5 + u2 * v6 + u1 * v7;
    final h0 = s0 * t0;
    final h8 = s7 * t1 + s6 * t2 + s5 * t3 + s4 * t4 + s3 * t5 + s2 * t6 + s1 * t7;

    var c = f0 + g0 + h8 - f8;
    var z0 = c & m28;
    c >>>= 28;
    var d = g8 + h0 - f0 + h8;
    var z8 = d & m28;
    d >>>= 28;

    final f1 = x1 * y0 + x0 * y1;
    final f9 = x7 * y2 + x6 * y3 + x5 * y4 + x4 * y5 + x3 * y6 + x2 * y7;
    final g1 = u1 * v0 + u0 * v1;
    final g9 = u7 * v2 + u6 * v3 + u5 * v4 + u4 * v5 + u3 * v6 + u2 * v7;
    final h1 = s1 * t0 + s0 * t1;
    final h9 = s7 * t2 + s6 * t3 + s5 * t4 + s4 * t5 + s3 * t6 + s2 * t7;

    c += f1 + g1 + h9 - f9;
    var z1 = c & m28;
    c >>>= 28;
    d += g9 + h1 - f1 + h9;
    var z9 = d & m28;
    d >>>= 28;

    final f2 = x2 * y0 + x1 * y1 + x0 * y2;
    final f10 = x7 * y3 + x6 * y4 + x5 * y5 + x4 * y6 + x3 * y7;
    final g2 = u2 * v0 + u1 * v1 + u0 * v2;
    final g10 = u7 * v3 + u6 * v4 + u5 * v5 + u4 * v6 + u3 * v7;
    final h2 = s2 * t0 + s1 * t1 + s0 * t2;
    final h10 = s7 * t3 + s6 * t4 + s5 * t5 + s4 * t6 + s3 * t7;

    c += f2 + g2 + h10 - f10;
    var z2 = c & m28;
    c >>>= 28;
    d += g10 + h2 - f2 + h10;
    var z10 = d & m28;
    d >>>= 28;

    final f3 = x3 * y0 + x2 * y1 + x1 * y2 + x0 * y3;
    final f11 = x7 * y4 + x6 * y5 + x5 * y6 + x4 * y7;
    final g3 = u3 * v0 + u2 * v1 + u1 * v2 + u0 * v3;
    final g11 = u7 * v4 + u6 * v5 + u5 * v6 + u4 * v7;
    final h3 = s3 * t0 + s2 * t1 + s1 * t2 + s0 * t3;
    final h11 = s7 * t4 + s6 * t5 + s5 * t6 + s4 * t7;

    c += f3 + g3 + h11 - f11;
    var z3 = c & m28;
    c >>>= 28;
    d += g11 + h3 - f3 + h11;
    var z11 = d & m28;
    d >>>= 28;

    final f4 = x4 * y0 + x3 * y1 + x2 * y2 + x1 * y3 + x0 * y4;
    final f12 = x7 * y5 + x6 * y6 + x5 * y7;
    final g4 = u4 * v0 + u3 * v1 + u2 * v2 + u1 * v3 + u0 * v4;
    final g12 = u7 * v5 + u6 * v6 + u5 * v7;
    final h4 = s4 * t0 + s3 * t1 + s2 * t2 + s1 * t3 + s0 * t4;
    final h12 = s7 * t5 + s6 * t6 + s5 * t7;

    c += f4 + g4 + h12 - f12;
    var z4 = c & m28;
    c >>>= 28;
    d += g12 + h4 - f4 + h12;
    var z12 = d & m28;
    d >>>= 28;

    final f5 = x5 * y0 + x4 * y1 + x3 * y2 + x2 * y3 + x1 * y4 + x0 * y5;
    final f13 = x7 * y6 + x6 * y7;
    final g5 = u5 * v0 + u4 * v1 + u3 * v2 + u2 * v3 + u1 * v4 + u0 * v5;
    final g13 = u7 * v6 + u6 * v7;
    final h5 = s5 * t0 + s4 * t1 + s3 * t2 + s2 * t3 + s1 * t4 + s0 * t5;
    final h13 = s7 * t6 + s6 * t7;

    c += f5 + g5 + h13 - f13;
    var z5 = c & m28;
    c >>>= 28;
    d += g13 + h5 - f5 + h13;
    var z13 = d & m28;
    d >>>= 28;

    final f6 = x6 * y0 + x5 * y1 + x4 * y2 + x3 * y3 + x2 * y4 + x1 * y5 + x0 * y6;
    final f14 = x7 * y7;
    final g6 = u6 * v0 + u5 * v1 + u4 * v2 + u3 * v3 + u2 * v4 + u1 * v5 + u0 * v6;
    final g14 = u7 * v7;
    final h6 = s6 * t0 + s5 * t1 + s4 * t2 + s3 * t3 + s2 * t4 + s1 * t5 + s0 * t6;
    final h14 = s7 * t7;

    c += f6 + g6 + h14 - f14;
    var z6 = c & m28;
    c >>>= 28;
    d += g14 + h6 - f6 + h14;
    var z14 = d & m28;
    d >>>= 28;

    final f7 = x7 * y0 + x6 * y1 + x5 * y2 + x4 * y3 + x3 * y4 + x2 * y5 + x1 * y6 + x0 * y7;
    final g7 = u7 * v0 + u6 * v1 + u5 * v2 + u4 * v3 + u3 * v4 + u2 * v5 + u1 * v6 + u0 * v7;
    final h7 = s7 * t0 + s6 * t1 + s5 * t2 + s4 * t3 + s3 * t4 + s2 * t5 + s1 * t6 + s0 * t7;

    c += f7 + g7;
    var z7 = c & m28;
    c >>>= 28;
    d += h7 - f7;
    var z15 = d & m28;
    d >>>= 28;

    c += d;

    c += z8;
    z8 = c & m28;
    c >>>= 28;
    d += z0;
    z0 = d & m28;
    d >>>= 28;
    z9 += c;
    z1 += d;

    z.setAll(0, [
      z0, z1, z2, z3, z4, z5, z6, z7, // 0 -7
      z8, z9, z10, z11, z12, z13, z14, z15,
    ]);
  }

  static void normalize(final Uint32List z) {
    _reduce(z, 1);
    _reduce(z, -1);
  }

  /// Calculate z = x^2 mod p.
  static void sqr(
    final Uint32List x,
    final Uint32List z,
  ) {
    final x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
    final x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];

    final u0 = x[8], u1 = x[9], u2 = x[10], u3 = x[11];
    final u4 = x[12], u5 = x[13], u6 = x[14], u7 = x[15];

    final x0_2 = x0 * 2;
    final x1_2 = x1 * 2;
    final x2_2 = x2 * 2;
    final x3_2 = x3 * 2;
    final x4_2 = x4 * 2;
    final x5_2 = x5 * 2;
    final x6_2 = x6 * 2;

    final u0_2 = u0 * 2;
    final u1_2 = u1 * 2;
    final u2_2 = u2 * 2;
    final u3_2 = u3 * 2;
    final u4_2 = u4 * 2;
    final u5_2 = u5 * 2;
    final u6_2 = u6 * 2;

    final s0 = x0 + u0;
    final s1 = x1 + u1;
    final s2 = x2 + u2;
    final s3 = x3 + u3;
    final s4 = x4 + u4;
    final s5 = x5 + u5;
    final s6 = x6 + u6;
    final s7 = x7 + u7;

    final s0_2 = s0 * 2;
    final s1_2 = s1 * 2;
    final s2_2 = s2 * 2;
    final s3_2 = s3 * 2;
    final s4_2 = s4 * 2;
    final s5_2 = s5 * 2;
    final s6_2 = s6 * 2;

    final f0 = x0 * x0;
    final f8 = x7 * x1_2 + x6 * x2_2 + x5 * x3_2 + x4 * x4;
    final g0 = u0 * u0;
    final g8 = u7 * u1_2 + u6 * u2_2 + u5 * u3_2 + u4 * u4;
    final h0 = s0 * s0;
    final h8 = s7 * s1_2 + s6 * s2_2 + s5 * s3_2 + s4 * s4;

    var c = f0 + g0 + h8 - f8;
    var z0 = c & m28;
    c >>>= 28;
    var d = g8 + h0 - f0 + h8;
    var z8 = d & m28;
    d >>>= 28;

    final f1 = x1 * x0_2;
    final f9 = x7 * x2_2 + x6 * x3_2 + x5 * x4_2;
    final g1 = u1 * u0_2;
    final g9 = u7 * u2_2 + u6 * u3_2 + u5 * u4_2;
    final h1 = s1 * s0_2;
    final h9 = s7 * s2_2 + s6 * s3_2 + s5 * s4_2;

    c += f1 + g1 + h9 - f9;
    var z1 = c & m28;
    c >>>= 28;
    d += g9 + h1 - f1 + h9;
    var z9 = d & m28;
    d >>>= 28;

    final f2 = x2 * x0_2 + x1 * x1;
    final f10 = x7 * x3_2 + x6 * x4_2 + x5 * x5;
    final g2 = u2 * u0_2 + u1 * u1;
    final g10 = u7 * u3_2 + u6 * u4_2 + u5 * u5;
    final h2 = s2 * s0_2 + s1 * s1;
    final h10 = s7 * s3_2 + s6 * s4_2 + s5 * s5;

    c += f2 + g2 + h10 - f10;
    var z2 = c & m28;
    c >>>= 28;
    d += g10 + h2 - f2 + h10;
    var z10 = d & m28;
    d >>>= 28;

    final f3 = x3 * x0_2 + x2 * x1_2;
    final f11 = x7 * x4_2 + x6 * x5_2;
    final g3 = u3 * u0_2 + u2 * u1_2;
    final g11 = u7 * u4_2 + u6 * u5_2;
    final h3 = s3 * s0_2 + s2 * s1_2;
    final h11 = s7 * s4_2 + s6 * s5_2;

    c += f3 + g3 + h11 - f11;
    var z3 = c & m28;
    c >>>= 28;
    d += g11 + h3 - f3 + h11;
    var z11 = d & m28;
    d >>>= 28;

    final f4 = x4 * x0_2 + x3 * x1_2 + x2 * x2;
    final f12 = x7 * x5_2 + x6 * x6;
    final g4 = u4 * u0_2 + u3 * u1_2 + u2 * u2;
    final g12 = u7 * u5_2 + u6 * u6;
    final h4 = s4 * s0_2 + s3 * s1_2 + s2 * s2;
    final h12 = s7 * s5_2 + s6 * s6;

    c += f4 + g4 + h12 - f12;
    var z4 = c & m28;
    c >>>= 28;
    d += g12 + h4 - f4 + h12;
    var z12 = d & m28;
    d >>>= 28;

    final f5 = x5 * x0_2 + x4 * x1_2 + x3 * x2_2;
    final f13 = x7 * x6_2;
    final g5 = u5 * u0_2 + u4 * u1_2 + u3 * u2_2;
    final g13 = u7 * u6_2;
    final h5 = s5 * s0_2 + s4 * s1_2 + s3 * s2_2;
    final h13 = s7 * s6_2;

    c += f5 + g5 + h13 - f13;
    var z5 = c & m28;
    c >>>= 28;
    d += g13 + h5 - f5 + h13;
    var z13 = d & m28;
    d >>>= 28;

    final f6 = x6 * x0_2 + x5 * x1_2 + x4 * x2_2 + x3 * x3;
    final f14 = x7 * x7;
    final g6 = u6 * u0_2 + u5 * u1_2 + u4 * u2_2 + u3 * u3;
    final g14 = u7 * u7;
    final h6 = s6 * s0_2 + s5 * s1_2 + s4 * s2_2 + s3 * s3;
    final h14 = s7 * s7;

    c += f6 + g6 + h14 - f14;
    var z6 = c & m28;
    c >>>= 28;
    d += g14 + h6 - f6 + h14;
    var z14 = d & m28;
    d >>>= 28;

    final f7 = x7 * x0_2 + x6 * x1_2 + x5 * x2_2 + x4 * x3_2;
    final g7 = u7 * u0_2 + u6 * u1_2 + u5 * u2_2 + u4 * u3_2;
    final h7 = s7 * s0_2 + s6 * s1_2 + s5 * s2_2 + s4 * s3_2;

    c += f7 + g7;
    var z7 = c & m28;
    c >>>= 28;
    d += h7 - f7;
    var z15 = d & m28;
    d >>>= 28;

    c += d;

    c += z8;
    z8 = c & m28;
    c >>>= 28;
    d += z0;
    z0 = d & m28;
    d >>>= 28;
    z9 += c;
    z1 += d;

    z.setAll(0, [
      z0, z1, z2, z3, z4, z5, z6, z7, // 0 -7
      z8, z9, z10, z11, z12, z13, z14, z15,
    ]);
  }

  static void nSqr(
    final Uint32List x,
    final int n,
    final Uint32List z,
  ) {
    sqr(x, z);
    var m = n;

    while (--m > 0) {
      sqr(z, z);
    }
  }

  /// Calculate z = x-y mod p.
  static void sub(
    final Uint32List x,
    final Uint32List y,
    final Uint32List z,
  ) {
    final x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
    final x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
    final x8 = x[8], x9 = x[9], x10 = x[10], x11 = x[11];
    final x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];
    final y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3];
    final y4 = y[4], y5 = y[5], y6 = y[6], y7 = y[7];
    final y8 = y[8], y9 = y[9], y10 = y[10], y11 = y[11];
    final y12 = y[12], y13 = y[13], y14 = y[14], y15 = y[15];

    var z0 = x0 + 0x1ffffffe - y0;
    var z1 = x1 + 0x1ffffffe - y1;
    var z2 = x2 + 0x1ffffffe - y2;
    var z3 = x3 + 0x1ffffffe - y3;
    var z4 = x4 + 0x1ffffffe - y4;
    var z5 = x5 + 0x1ffffffe - y5;
    var z6 = x6 + 0x1ffffffe - y6;
    var z7 = x7 + 0x1ffffffe - y7;
    var z8 = x8 + 0x1ffffffc - y8;
    var z9 = x9 + 0x1ffffffe - y9;
    var z10 = x10 + 0x1ffffffe - y10;
    var z11 = x11 + 0x1ffffffe - y11;
    var z12 = x12 + 0x1ffffffe - y12;
    var z13 = x13 + 0x1ffffffe - y13;
    var z14 = x14 + 0x1ffffffe - y14;
    var z15 = x15 + 0x1ffffffe - y15;

    z2 += z1 >>> 28;
    z1 &= m28;
    z6 += z5 >>> 28;
    z5 &= m28;
    z10 += z9 >>> 28;
    z9 &= m28;
    z14 += z13 >>> 28;
    z13 &= m28;

    z3 += z2 >>> 28;
    z2 &= m28;
    z7 += z6 >>> 28;
    z6 &= m28;
    z11 += z10 >>> 28;
    z10 &= m28;
    z15 += z14 >>> 28;
    z14 &= m28;

    final t = z15 >>> 28;
    z15 &= m28;
    z0 += t;
    z8 += t;

    z4 += z3 >>> 28;
    z3 &= m28;
    z8 += z7 >>> 28;
    z7 &= m28;
    z12 += z11 >>> 28;
    z11 &= m28;

    z1 += z0 >>> 28;
    z0 &= m28;
    z5 += z4 >>> 28;
    z4 &= m28;
    z9 += z8 >>> 28;
    z8 &= m28;
    z13 += z12 >>> 28;
    z12 &= m28;

    z.setAll(0, [
      z0, z1, z2, z3, z4, z5, z6, z7, // 0 -7
      z8, z9, z10, z11, z12, z13, z14, z15,
    ]);
  }

  /// Calculate z = x^k mod p, where k = (p-3)/4.
  static void _powPm3d4(
    final Uint32List x,
    final Uint32List z,
  ) {
    final x2 = create();
    sqr(x, x2);
    mul(x, x2, x2);
    final x3 = create();
    sqr(x2, x3);
    mul(x, x3, x3);
    final x6 = create();
    nSqr(x3, 3, x6);
    mul(x3, x6, x6);
    final x9 = create();
    nSqr(x6, 3, x9);
    mul(x3, x9, x9);
    final x18 = create();
    nSqr(x9, 9, x18);
    mul(x9, x18, x18);
    final x19 = create();
    sqr(x18, x19);
    mul(x, x19, x19);
    final x37 = create();
    nSqr(x19, 18, x37);
    mul(x18, x37, x37);
    final x74 = create();
    nSqr(x37, 37, x74);
    mul(x37, x74, x74);
    final x111 = create();
    nSqr(x74, 37, x111);
    mul(x37, x111, x111);
    final x222 = create();
    nSqr(x111, 111, x222);
    mul(x111, x222, x222);
    final x223 = create();
    sqr(x222, x223);
    mul(x, x223, x223);

    final t = create();
    nSqr(x223, 223, t);
    mul(t, x222, z);
  }

  static void _reduce(
    final Uint32List z,
    final int x,
  ) {
    final u = z[15], z15 = u & m28;
    final t = (u >>> 28) + x;

    var cc = t;
    for (var i = 0; i < 8; ++i) {
      cc += z[i];
      z[i] = cc & m28;
      cc >>>= 28;
    }
    cc += t;
    for (var i = 8; i < 15; ++i) {
      cc += z[i];
      z[i] = cc & m28;
      cc >>>= 28;
    }
    z[15] = z15 + cc;
  }
}
