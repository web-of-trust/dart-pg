// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/api.dart';

import 'dart:typed_data';

import '../../helpers.dart';
import 'base_cipher.dart';

/// A class that provides Twofish encryption operations.
class TwofishEngine extends BaseCipher {
  static const _p = [
    [
      0xA9,
      0x67,
      0xB3,
      0xE8,
      0x04,
      0xFD,
      0xA3,
      0x76,
      0x9A,
      0x92,
      0x80,
      0x78,
      0xE4,
      0xDD,
      0xD1,
      0x38,
      0x0D,
      0xC6,
      0x35,
      0x98,
      0x18,
      0xF7,
      0xEC,
      0x6C,
      0x43,
      0x75,
      0x37,
      0x26,
      0xFA,
      0x13,
      0x94,
      0x48,
      0xF2,
      0xD0,
      0x8B,
      0x30,
      0x84,
      0x54,
      0xDF,
      0x23,
      0x19,
      0x5B,
      0x3D,
      0x59,
      0xF3,
      0xAE,
      0xA2,
      0x82,
      0x63,
      0x01,
      0x83,
      0x2E,
      0xD9,
      0x51,
      0x9B,
      0x7C,
      0xA6,
      0xEB,
      0xA5,
      0xBE,
      0x16,
      0x0C,
      0xE3,
      0x61,
      0xC0,
      0x8C,
      0x3A,
      0xF5,
      0x73,
      0x2C,
      0x25,
      0x0B,
      0xBB,
      0x4E,
      0x89,
      0x6B,
      0x53,
      0x6A,
      0xB4,
      0xF1,
      0xE1,
      0xE6,
      0xBD,
      0x45,
      0xE2,
      0xF4,
      0xB6,
      0x66,
      0xCC,
      0x95,
      0x03,
      0x56,
      0xD4,
      0x1C,
      0x1E,
      0xD7,
      0xFB,
      0xC3,
      0x8E,
      0xB5,
      0xE9,
      0xCF,
      0xBF,
      0xBA,
      0xEA,
      0x77,
      0x39,
      0xAF,
      0x33,
      0xC9,
      0x62,
      0x71,
      0x81,
      0x79,
      0x09,
      0xAD,
      0x24,
      0xCD,
      0xF9,
      0xD8,
      0xE5,
      0xC5,
      0xB9,
      0x4D,
      0x44,
      0x08,
      0x86,
      0xE7,
      0xA1,
      0x1D,
      0xAA,
      0xED,
      0x06,
      0x70,
      0xB2,
      0xD2,
      0x41,
      0x7B,
      0xA0,
      0x11,
      0x31,
      0xC2,
      0x27,
      0x90,
      0x20,
      0xF6,
      0x60,
      0xFF,
      0x96,
      0x5C,
      0xB1,
      0xAB,
      0x9E,
      0x9C,
      0x52,
      0x1B,
      0x5F,
      0x93,
      0x0A,
      0xEF,
      0x91,
      0x85,
      0x49,
      0xEE,
      0x2D,
      0x4F,
      0x8F,
      0x3B,
      0x47,
      0x87,
      0x6D,
      0x46,
      0xD6,
      0x3E,
      0x69,
      0x64,
      0x2A,
      0xCE,
      0xCB,
      0x2F,
      0xFC,
      0x97,
      0x05,
      0x7A,
      0xAC,
      0x7F,
      0xD5,
      0x1A,
      0x4B,
      0x0E,
      0xA7,
      0x5A,
      0x28,
      0x14,
      0x3F,
      0x29,
      0x88,
      0x3C,
      0x4C,
      0x02,
      0xB8,
      0xDA,
      0xB0,
      0x17,
      0x55,
      0x1F,
      0x8A,
      0x7D,
      0x57,
      0xC7,
      0x8D,
      0x74,
      0xB7,
      0xC4,
      0x9F,
      0x72,
      0x7E,
      0x15,
      0x22,
      0x12,
      0x58,
      0x07,
      0x99,
      0x34,
      0x6E,
      0x50,
      0xDE,
      0x68,
      0x65,
      0xBC,
      0xDB,
      0xF8,
      0xC8,
      0xA8,
      0x2B,
      0x40,
      0xDC,
      0xFE,
      0x32,
      0xA4,
      0xCA,
      0x10,
      0x21,
      0xF0,
      0xD3,
      0x5D,
      0x0F,
      0x00,
      0x6F,
      0x9D,
      0x36,
      0x42,
      0x4A,
      0x5E,
      0xC1,
      0xE0,
    ],
    [
      0x75,
      0xF3,
      0xC6,
      0xF4,
      0xDB,
      0x7B,
      0xFB,
      0xC8,
      0x4A,
      0xD3,
      0xE6,
      0x6B,
      0x45,
      0x7D,
      0xE8,
      0x4B,
      0xD6,
      0x32,
      0xD8,
      0xFD,
      0x37,
      0x71,
      0xF1,
      0xE1,
      0x30,
      0x0F,
      0xF8,
      0x1B,
      0x87,
      0xFA,
      0x06,
      0x3F,
      0x5E,
      0xBA,
      0xAE,
      0x5B,
      0x8A,
      0x00,
      0xBC,
      0x9D,
      0x6D,
      0xC1,
      0xB1,
      0x0E,
      0x80,
      0x5D,
      0xD2,
      0xD5,
      0xA0,
      0x84,
      0x07,
      0x14,
      0xB5,
      0x90,
      0x2C,
      0xA3,
      0xB2,
      0x73,
      0x4C,
      0x54,
      0x92,
      0x74,
      0x36,
      0x51,
      0x38,
      0xB0,
      0xBD,
      0x5A,
      0xFC,
      0x60,
      0x62,
      0x96,
      0x6C,
      0x42,
      0xF7,
      0x10,
      0x7C,
      0x28,
      0x27,
      0x8C,
      0x13,
      0x95,
      0x9C,
      0xC7,
      0x24,
      0x46,
      0x3B,
      0x70,
      0xCA,
      0xE3,
      0x85,
      0xCB,
      0x11,
      0xD0,
      0x93,
      0xB8,
      0xA6,
      0x83,
      0x20,
      0xFF,
      0x9F,
      0x77,
      0xC3,
      0xCC,
      0x03,
      0x6F,
      0x08,
      0xBF,
      0x40,
      0xE7,
      0x2B,
      0xE2,
      0x79,
      0x0C,
      0xAA,
      0x82,
      0x41,
      0x3A,
      0xEA,
      0xB9,
      0xE4,
      0x9A,
      0xA4,
      0x97,
      0x7E,
      0xDA,
      0x7A,
      0x17,
      0x66,
      0x94,
      0xA1,
      0x1D,
      0x3D,
      0xF0,
      0xDE,
      0xB3,
      0x0B,
      0x72,
      0xA7,
      0x1C,
      0xEF,
      0xD1,
      0x53,
      0x3E,
      0x8F,
      0x33,
      0x26,
      0x5F,
      0xEC,
      0x76,
      0x2A,
      0x49,
      0x81,
      0x88,
      0xEE,
      0x21,
      0xC4,
      0x1A,
      0xEB,
      0xD9,
      0xC5,
      0x39,
      0x99,
      0xCD,
      0xAD,
      0x31,
      0x8B,
      0x01,
      0x18,
      0x23,
      0xDD,
      0x1F,
      0x4E,
      0x2D,
      0xF9,
      0x48,
      0x4F,
      0xF2,
      0x65,
      0x8E,
      0x78,
      0x5C,
      0x58,
      0x19,
      0x8D,
      0xE5,
      0x98,
      0x57,
      0x67,
      0x7F,
      0x05,
      0x64,
      0xAF,
      0x63,
      0xB6,
      0xFE,
      0xF5,
      0xB7,
      0x3C,
      0xA5,
      0xCE,
      0xE9,
      0x68,
      0x44,
      0xE0,
      0x4D,
      0x43,
      0x69,
      0x29,
      0x2E,
      0xAC,
      0x15,
      0x59,
      0xA8,
      0x0A,
      0x9E,
      0x6E,
      0x47,
      0xDF,
      0x34,
      0x35,
      0x6A,
      0xCF,
      0xDC,
      0x22,
      0xC9,
      0xC0,
      0x9B,
      0x89,
      0xD4,
      0xED,
      0xAB,
      0x12,
      0xA2,
      0x0D,
      0x52,
      0xBB,
      0x02,
      0x2F,
      0xA9,
      0xD7,
      0x61,
      0x1E,
      0xB4,
      0x50,
      0x04,
      0xF6,
      0xC2,
      0x16,
      0x25,
      0x86,
      0x56,
      0x55,
      0x09,
      0xBE,
      0x91,
    ],
  ];

  /// Define the fixed p0/p1 permutations used in keyed S-box lookup.
  /// By changing the following constant definitions, the S-boxes will
  /// automatically get changed in the Twofish engine.
  static const _p00 = 1;
  static const _p01 = 0;
  static const _p02 = 0;
  static const _p03 = _p01 ^ 1;
  static const _p04 = 1;

  static const _p10 = 0;
  static const _p11 = 0;
  static const _p12 = 1;
  static const _p13 = _p11 ^ 1;
  static const _p14 = 0;

  static const _p20 = 1;
  static const _p21 = 1;
  static const _p22 = 0;
  static const _p23 = _p21 ^ 1;
  static const _p24 = 0;

  static const _p30 = 0;
  static const _p31 = 1;
  static const _p32 = 1;
  static const _p33 = _p31 ^ 1;
  static const _p34 = 1;

  /// Primitive polynomial for GF(256)
  static const _gf256Fdbk = 0x169;
  static const _gf256Fdbk2 = _gf256Fdbk ~/ 2;
  static const _gf256Fdbk4 = _gf256Fdbk ~/ 4;
  static const _rsGfFdbk = 0x14d;

  static const _rounds = 16;
  static const _maxRounds = 16;
  static const _blockSize = 16;
  static const _maxKeyBits = 256;

  static const _inputWhiten = 0;
  static const _outputWhiten = _inputWhiten + _blockSize ~/ 4;
  static const _roundSubkeys = _outputWhiten + _blockSize ~/ 4;

  static const _totalSubkeys = _roundSubkeys + 2 * _maxRounds;

  static const _skStep = 0x02020202;
  static const _skBump = 0x01010101;
  static const _skRotl = 9;

  bool _forEncryption = false;
  late Uint8List _workingKey;

  final List<int> _gMDS0 = List<int>.filled(_maxKeyBits, 0);
  final List<int> _gMDS1 = List<int>.filled(_maxKeyBits, 0);
  final List<int> _gMDS2 = List<int>.filled(_maxKeyBits, 0);
  final List<int> _gMDS3 = List<int>.filled(_maxKeyBits, 0);

  final List<int> _gSubKeys = List<int>.filled(_totalSubkeys, 0);
  final List<int> _gSBox = List<int>.filled(4 * _maxKeyBits, 0);

  int _k64Cnt = 0;

  @override
  String get algorithmName => 'Twofish';

  @override
  int get blockSize => _blockSize;

  TwofishEngine() {
    final m1 = List<int>.filled(2, 0);
    final mX = List<int>.filled(2, 0);
    final mY = List<int>.filled(2, 0);
    int j;

    for (int i = 0; i < _maxKeyBits; i++) {
      j = _p[0][i] & 0xff;
      m1[0] = j;
      mX[0] = _mxX(j) & 0xff;
      mY[0] = _mxY(j) & 0xff;

      j = _p[1][i] & 0xff;
      m1[1] = j;
      mX[1] = _mxX(j) & 0xff;
      mY[1] = _mxY(j) & 0xff;

      _gMDS0[i] = m1[_p00] | mX[_p00] << 8 | mY[_p00] << 16 | mY[_p00] << 24;

      _gMDS1[i] = mY[_p10] | mY[_p10] << 8 | mX[_p10] << 16 | m1[_p10] << 24;

      _gMDS2[i] = mX[_p20] | mY[_p20] << 8 | m1[_p20] << 16 | mY[_p20] << 24;

      _gMDS3[i] = mX[_p30] | m1[_p30] << 8 | mY[_p30] << 16 | mX[_p30] << 24;
    }
  }

  @override
  void init(bool forEncryption, CipherParameters? params) {
    if (params is KeyParameter) {
      _forEncryption = forEncryption;
      _workingKey = params.key;
      final keyBits = _workingKey.length * 8;
      if (!(keyBits == 128 || keyBits == 192 || keyBits == 256)) {
        throw ArgumentError('Key length not 128/192/256 bits.');
      }
      _k64Cnt = (_workingKey.length / 8) as int;
      _setKey(_workingKey);
    } else {
      throw ArgumentError('Invalid parameter passed to $algorithmName init - ${params.runtimeType}');
    }
  }

  @override
  int processBlock(Uint8List input, int inOff, Uint8List output, int outOff) {
    if (_workingKey.isEmpty) {
      throw StateError('$algorithmName not initialised');
    }
    if ((inOff + blockSize) > input.length) {
      throw ArgumentError('input buffer too short for $algorithmName engine');
    }
    if ((outOff + blockSize) > output.length) {
      throw ArgumentError('output buffer too short for $algorithmName engine');
    }

    if (_forEncryption) {
      _encryptBlock(input, inOff, output, outOff);
    } else {
      _decryptBlock(input, inOff, output, outOff);
    }

    return blockSize;
  }

  @override
  void reset() {}

  void _setKey(final Uint8List key) {
    final k32e = List<int>.filled(_maxKeyBits ~/ 64, 0);
    final k32o = List<int>.filled(_maxKeyBits ~/ 64, 0);

    final sBoxKeys = List<int>.filled(_maxKeyBits ~/ 64, 0);

    for (var i = 0; i < _k64Cnt; i++) {
      final p = i * 8;
      k32e[i] = key.sublist(p).toInt32();
      k32o[i] = key.sublist(p + 4).toInt32();

      sBoxKeys[_k64Cnt - 1 - i] = _rsMdsEncode(k32e[i], k32o[i]);
    }

    int A, B;
    for (var i = 0; i < _totalSubkeys ~/ 2; i++) {
      final q = i * _skStep;
      A = _f32(q, k32e);
      B = _f32(q + _skBump, k32o);
      B = B.rotateLeft(8);
      A += B;
      _gSubKeys[i * 2] = A;
      A += B;
      _gSubKeys[i * 2 + 1] = A.rotateLeft(_skRotl);
    }

    final k0 = sBoxKeys[0];
    final k1 = sBoxKeys[1];
    final k2 = sBoxKeys[2];
    final k3 = sBoxKeys[3];
    int b0, b1, b2, b3;

    for (var i = 0; i < _maxKeyBits; i++) {
      b0 = b1 = b2 = b3 = i;
      switch (_k64Cnt & 3) {
        case 1:
          _gSBox[i * 2] = _gMDS0[(_p[_p01][b0] & 0xff) ^ _b0(k0)];
          _gSBox[i * 2 + 1] = _gMDS1[(_p[_p11][b1] & 0xff) ^ _b1(k0)];
          _gSBox[i * 2 + 0x200] = _gMDS2[(_p[_p21][b2] & 0xff) ^ _b2(k0)];
          _gSBox[i * 2 + 0x201] = _gMDS3[(_p[_p31][b3] & 0xff) ^ _b3(k0)];
          break;
        case 0: // 256 bits of key
          b0 = (_p[_p04][b0] & 0xff) ^ _b0(k3);
          b1 = (_p[_p14][b1] & 0xff) ^ _b1(k3);
          b2 = (_p[_p24][b2] & 0xff) ^ _b2(k3);
          b3 = (_p[_p34][b3] & 0xff) ^ _b3(k3);

          b0 = (_p[_p03][b0] & 0xff) ^ _b0(k2);
          b1 = (_p[_p13][b1] & 0xff) ^ _b1(k2);
          b2 = (_p[_p23][b2] & 0xff) ^ _b2(k2);
          b3 = (_p[_p33][b3] & 0xff) ^ _b3(k2);

          _gSBox[i * 2] = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)];
          _gSBox[i * 2 + 1] = _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)];
          _gSBox[i * 2 + 0x200] = _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)];
          _gSBox[i * 2 + 0x201] = _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];
          break;
        case 3: // 192 bits of key
          b0 = (_p[_p03][b0] & 0xff) ^ _b0(k2);
          b1 = (_p[_p13][b1] & 0xff) ^ _b1(k2);
          b2 = (_p[_p23][b2] & 0xff) ^ _b2(k2);
          b3 = (_p[_p33][b3] & 0xff) ^ _b3(k2);

          _gSBox[i * 2] = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)];
          _gSBox[i * 2 + 1] = _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)];
          _gSBox[i * 2 + 0x200] = _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)];
          _gSBox[i * 2 + 0x201] = _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];
          break;
        case 2: // 128 bits of key
          _gSBox[i * 2] = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)];
          _gSBox[i * 2 + 1] = _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)];
          _gSBox[i * 2 + 0x200] = _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)];
          _gSBox[i * 2 + 0x201] = _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];
          break;
      }
    }
  }

  /// Encrypt the given input starting at the given offset and place
  /// the result in the provided buffer starting at the given offset.
  /// The input will be an exact multiple of our blocksize.
  void _encryptBlock(final Uint8List src, final int srcIndex, final Uint8List dst, final int dstIndex) {
    var x0 = src.sublist(srcIndex).toLeInt32() ^ _gSubKeys[_inputWhiten];
    var x1 = src.sublist(srcIndex + 4).toLeInt32() ^ _gSubKeys[_inputWhiten + 1];
    var x2 = src.sublist(srcIndex + 8).toLeInt32() ^ _gSubKeys[_inputWhiten + 2];
    var x3 = src.sublist(srcIndex + 12).toLeInt32() ^ _gSubKeys[_inputWhiten + 3];

    var k = _roundSubkeys;
    int t0, t1;
    for (var r = 0; r < _rounds; r += 2) {
      t0 = _fe32_0(x0);
      t1 = _fe32_3(x1);
      x2 ^= t0 + t1 + _gSubKeys[k++];
      x2 = x2.rotateRight(1);
      x3 = x3.rotateLeft(1) ^ (t0 + 2 * t1 + _gSubKeys[k++]);

      t0 = _fe32_0(x2);
      t1 = _fe32_3(x3);
      x0 ^= t0 + t1 + _gSubKeys[k++];
      x0 = x0.rotateRight(1);
      x1 = x1.rotateLeft(1) ^ (t0 + 2 * t1 + _gSubKeys[k++]);
    }

    dst.setAll(dstIndex, (x2 ^ _gSubKeys[_outputWhiten]).toLe32Bytes());
    dst.setAll(dstIndex + 4, (x3 ^ _gSubKeys[_outputWhiten + 1]).toLe32Bytes());
    dst.setAll(dstIndex + 8, (x0 ^ _gSubKeys[_outputWhiten + 2]).toLe32Bytes());
    dst.setAll(dstIndex + 12, (x1 ^ _gSubKeys[_outputWhiten + 3]).toLe32Bytes());
  }

  /// Decrypt the given input starting at the given offset and place
  /// the result in the provided buffer starting at the given offset.
  /// The input will be an exact multiple of our blocksize.
  void _decryptBlock(final Uint8List src, final int srcIndex, final Uint8List dst, final int dstIndex) {
    var x2 = src.sublist(srcIndex).toLeInt32() ^ _gSubKeys[_outputWhiten];
    var x3 = src.sublist(srcIndex + 4).toLeInt32() ^ _gSubKeys[_outputWhiten + 1];
    var x0 = src.sublist(srcIndex + 8).toLeInt32() ^ _gSubKeys[_outputWhiten + 2];
    var x1 = src.sublist(srcIndex + 12).toLeInt32() ^ _gSubKeys[_outputWhiten + 3];

    var k = _roundSubkeys + 2 * _rounds - 1;
    int t0, t1;
    for (int r = 0; r < _rounds; r += 2) {
      t0 = _fe32_0(x2);
      t1 = _fe32_3(x3);
      x1 ^= t0 + 2 * t1 + _gSubKeys[k--];
      x0 = x0.rotateLeft(1) ^ (t0 + t1 + _gSubKeys[k--]);
      x1 = x1.rotateRight(1);

      t0 = _fe32_0(x0);
      t1 = _fe32_3(x1);
      x3 ^= t0 + 2 * t1 + _gSubKeys[k--];
      x2 = x2.rotateLeft(1) ^ (t0 + t1 + _gSubKeys[k--]);
      x3 = x3.rotateRight(1);
    }

    dst.setAll(dstIndex, (x0 ^ _gSubKeys[_inputWhiten]).toLe32Bytes());
    dst.setAll(dstIndex + 4, (x1 ^ _gSubKeys[_inputWhiten + 1]).toLe32Bytes());
    dst.setAll(dstIndex + 8, (x2 ^ _gSubKeys[_inputWhiten + 2]).toLe32Bytes());
    dst.setAll(dstIndex + 12, (x3 ^ _gSubKeys[_inputWhiten + 3]).toLe32Bytes());
  }

  int _f32(final int x, final List<int> k32) {
    int b0 = _b0(x);
    int b1 = _b1(x);
    int b2 = _b2(x);
    int b3 = _b3(x);
    int k0 = k32[0];
    int k1 = k32[1];
    int k2 = k32[2];
    int k3 = k32[3];

    int result = 0;
    switch (_k64Cnt & 3) {
      case 1:
        result = _gMDS0[(_p[_p01][b0] & 0xff) ^ _b0(k0)] ^
            _gMDS1[(_p[_p11][b1] & 0xff) ^ _b1(k0)] ^
            _gMDS2[(_p[_p21][b2] & 0xff) ^ _b2(k0)] ^
            _gMDS3[(_p[_p31][b3] & 0xff) ^ _b3(k0)];
        break;
      case 0: /* 256 bits of key */
        b0 = (_p[_p04][b0] & 0xff) ^ _b0(k3);
        b1 = (_p[_p14][b1] & 0xff) ^ _b1(k3);
        b2 = (_p[_p24][b2] & 0xff) ^ _b2(k3);
        b3 = (_p[_p34][b3] & 0xff) ^ _b3(k3);

        b0 = (_p[_p03][b0] & 0xff) ^ _b0(k2);
        b1 = (_p[_p13][b1] & 0xff) ^ _b1(k2);
        b2 = (_p[_p23][b2] & 0xff) ^ _b2(k2);
        b3 = (_p[_p33][b3] & 0xff) ^ _b3(k2);

        result = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)] ^
            _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)] ^
            _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)] ^
            _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];

        break;
      case 3:
        b0 = (_p[_p03][b0] & 0xff) ^ _b0(k2);
        b1 = (_p[_p13][b1] & 0xff) ^ _b1(k2);
        b2 = (_p[_p23][b2] & 0xff) ^ _b2(k2);
        b3 = (_p[_p33][b3] & 0xff) ^ _b3(k2);

        result = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)] ^
            _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)] ^
            _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)] ^
            _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];
        break;
      case 2:
        result = _gMDS0[(_p[_p01][(_p[_p02][b0] & 0xff) ^ _b0(k1)] & 0xff) ^ _b0(k0)] ^
            _gMDS1[(_p[_p11][(_p[_p12][b1] & 0xff) ^ _b1(k1)] & 0xff) ^ _b1(k0)] ^
            _gMDS2[(_p[_p21][(_p[_p22][b2] & 0xff) ^ _b2(k1)] & 0xff) ^ _b2(k0)] ^
            _gMDS3[(_p[_p31][(_p[_p32][b3] & 0xff) ^ _b3(k1)] & 0xff) ^ _b3(k0)];
        break;
    }
    return result;
  }

  /// Use (12, 8) Reed-Solomon code over GF(256) to produce
  /// a key S-box 32-bit entity from 2 key material 32-bit entities.
  int _rsMdsEncode(final int k0, final int k1) {
    int r = k1;

    /// shift 1 byte at a time
    for (int i = 0; i < 4; i++) {
      r = _rsRem(r);
    }
    r ^= k0;
    for (int i = 0; i < 4; i++) {
      r = _rsRem(r);
    }

    return r;
  }

  /// Reed-Solomon code parameters: (12,8) reversible code:
  /// g(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
  /// where a = primitive root of field generator 0x14D
  int _rsRem(int x) {
    final b = ((x >>> 24) & 0xff);
    final g2 = ((b << 1) ^ ((b & 0x80) != 0 ? _rsGfFdbk : 0)) & 0xff;
    final g3 = ((b >>> 1) ^ ((b & 0x01) != 0 ? (_rsGfFdbk >>> 1) : 0)) ^ g2;
    return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
  }

  int _lfsr1(int x) {
    return (x >> 1) ^ (((x & 0x01) != 0) ? _gf256Fdbk2 : 0);
  }

  int _lfsr2(int x) {
    return (x >> 2) ^ (((x & 0x02) != 0) ? _gf256Fdbk2 : 0) ^ (((x & 0x01) != 0) ? _gf256Fdbk4 : 0);
  }

  int _mxX(int x) {
    return x ^ _lfsr2(x);
  }

  int _mxY(int x) {
    return x ^ _lfsr1(x) ^ _lfsr2(x);
  }

  int _b0(int x) {
    return x & 0xff;
  }

  int _b1(int x) {
    return (x >>> 8) & 0xff;
  }

  int _b2(int x) {
    return (x >>> 16) & 0xff;
  }

  int _b3(int x) {
    return (x >>> 24) & 0xff;
  }

  int _fe32_0(int x) {
    return _gSBox[0x000 + 2 * (x & 0xff)] ^
        _gSBox[0x001 + 2 * ((x >>> 8) & 0xff)] ^
        _gSBox[0x200 + 2 * ((x >>> 16) & 0xff)] ^
        _gSBox[0x201 + 2 * ((x >>> 24) & 0xff)];
  }

  int _fe32_3(int x) {
    return _gSBox[0x000 + 2 * ((x >>> 24) & 0xff)] ^
        _gSBox[0x001 + 2 * (x & 0xff)] ^
        _gSBox[0x200 + 2 * ((x >>> 8) & 0xff)] ^
        _gSBox[0x201 + 2 * ((x >>> 16) & 0xff)];
  }
}
