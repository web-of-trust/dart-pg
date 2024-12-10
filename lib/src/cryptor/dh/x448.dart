/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../math/fp448.dart';

/// Implementation of rfc-7748 x448
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class X448 {
  static const payloadSize = 56;
  static const a24 = 39082; // (156326 + 2) % 4;
  static const mask_8 = 0xff;

  /// Calculate a scalar point multiplication from base scalar
  static Uint8List scalarMultBase(
    final Uint8List k, [
    final int kOff = 0,
  ]) {
    final u = Uint8List(payloadSize);
    u[0] = 5;
    return X448.scalarMult(k, u, kOff);
  }

  /// Calculate a generic scalar point multiplication
  static Uint8List scalarMult(
    final Uint8List k,
    final Uint8List u, [
    final int kOff = 0,
    final int uOff = 0,
  ]) {
    final n = _decodeScalar(k, kOff);

    final x1 = decode(u, uOff);
    final x2 = Fp448.create();
    x2.setAll(0, x1);
    final z2 = Fp448.create();
    z2[0] = 1;
    final x3 = Fp448.create();
    x3[0] = 1;
    final z3 = Fp448.create();

    final t1 = Fp448.create();
    final t2 = Fp448.create();

    var bit = 447, swap = 1;
    do {
      Fp448.add(x3, z3, t1);
      Fp448.sub(x3, z3, x3);

      Fp448.add(x2, z2, z3);
      Fp448.sub(x2, z2, x2);

      Fp448.mul(t1, x2, t1);
      Fp448.mul(x3, z3, x3);

      Fp448.sqr(z3, z3);
      Fp448.sqr(x2, x2);

      Fp448.sub(z3, x2, t2);
      Fp448.mulA24(t2, a24, z2);
      Fp448.add(z2, x2, z2);
      Fp448.mul(z2, t2, z2);
      Fp448.mul(x2, z3, x2);

      Fp448.sub(t1, x3, z3);
      Fp448.add(t1, x3, x3);
      Fp448.sqr(x3, x3);
      Fp448.sqr(z3, z3);
      Fp448.mul(z3, x1, z3);

      --bit;

      final word = bit >>> 5;
      final shift = bit & 0x1F;
      final kt = (n[word] >>> shift) & 1;
      swap ^= kt;
      Fp448.cswap(swap, x2, x3);
      Fp448.cswap(swap, z2, z3);
      swap = kt;
    } while (bit >= 2);

    for (var i = 0; i < 2; ++i) {
      _pointDouble(x2, z2);
    }

    Fp448.inv(z2, z2);
    Fp448.mul(x2, z2, x2);
    Fp448.normalize(x2);

    return encode(x2);
  }

  static Uint32List decode(
    final Uint8List bytes, [
    final int off = 0,
  ]) {
    final z = Fp448.create();
    _decode56(bytes, z, off);
    _decode56(bytes, z, off + 7, 2);
    _decode56(bytes, z, off + 14, 4);
    _decode56(bytes, z, off + 21, 6);
    _decode56(bytes, z, off + 28, 8);
    _decode56(bytes, z, off + 35, 10);
    _decode56(bytes, z, off + 42, 12);
    _decode56(bytes, z, off + 49, 14);
    return z;
  }

  static Uint8List encode(
    final Uint32List x, [
    final int off = 0,
  ]) {
    final z = Uint8List(payloadSize);
    _encode56(x, z, off);
    _encode56(x, z, off + 2, 7);
    _encode56(x, z, off + 4, 14);
    _encode56(x, z, off + 6, 21);
    _encode56(x, z, off + 8, 28);
    _encode56(x, z, off + 10, 35);
    _encode56(x, z, off + 12, 42);
    _encode56(x, z, off + 14, 49);
    return z;
  }

  static void _pointDouble(
    final Uint32List x,
    final Uint32List z,
  ) {
    final a = Fp448.create();
    final b = Fp448.create();

    Fp448.add(x, z, a);
    Fp448.sub(x, z, b);
    Fp448.sqr(a, a);
    Fp448.sqr(b, b);
    Fp448.mul(a, b, x);
    Fp448.sub(a, b, a);
    Fp448.mulA24(a, a24, z);
    Fp448.add(z, b, z);
    Fp448.mul(z, a, z);
  }

  static Uint32List _decodeScalar(
    final Uint8List bytes,
    final int off,
  ) {
    final n = Uint32List(14);
    for (var i = 0; i < 14; ++i) {
      n[i] = _decode32(bytes, off + i * 4);
    }

    n[0] &= 0xfffffffc;
    n[13] |= 0x80000000;
    return n;
  }

  static int _decode24(
    final Uint8List bytes, [
    final int off = 0,
  ]) {
    var n = bytes[off];
    n |= bytes[off + 1] << 8;
    n |= bytes[off + 2] << 16;
    return n;
  }

  static int _decode32(
    final Uint8List bytes, [
    final int off = 0,
  ]) {
    var n = bytes[off];
    n |= bytes[off + 1] << 8;
    n |= bytes[off + 2] << 16;
    n |= bytes[off + 3] << 24;
    return n;
  }

  static void _decode56(
    final Uint8List bytes,
    final Uint32List z, [
    final int off = 0,
    final int zOff = 0,
  ]) {
    final lo = _decode32(bytes, off);
    final hi = _decode24(bytes, off + 4);
    z[zOff] = lo & Fp448.m28;
    z[zOff + 1] = (lo >>> 28) | (hi << 4);
  }

  static void _encode24(
    final int n,
    final Uint8List bytes, [
    final int off = 0,
  ]) {
    bytes[off] = n & mask_8;
    bytes[off + 1] = (n >>> 8) & mask_8;
    bytes[off + 2] = (n >>> 16) & mask_8;
  }

  static void _encode32(
    final int n,
    final Uint8List bytes, [
    final int off = 0,
  ]) {
    bytes[off] = n & mask_8;
    bytes[off + 1] = (n >>> 8) & mask_8;
    bytes[off + 2] = (n >>> 16) & mask_8;
    bytes[off + 3] = (n >>> 24) & mask_8;
  }

  static void _encode56(
    final Uint32List x,
    final Uint8List bytes, [
    final int xOff = 0,
    final int off = 0,
  ]) {
    final lo = x[xOff], hi = x[xOff + 1];
    _encode32(lo | (hi << 28), bytes, off);
    _encode24(hi >>> 4, bytes, off + 4);
  }
}
