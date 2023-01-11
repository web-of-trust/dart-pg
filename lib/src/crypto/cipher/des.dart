// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/api.dart';

import 'dart:typed_data';

import '../../helpers.dart';
import 'base_cipher.dart';

/// A class that provides a basic DES engine.
class DESEngine extends BaseCipher {
  static const _bytebit = [128, 64, 32, 16, 8, 4, 2, 1];

  static const _bigbyte = [
    0x800000,
    0x400000,
    0x200000,
    0x100000,
    0x80000,
    0x40000,
    0x20000,
    0x10000,
    0x8000,
    0x4000,
    0x2000,
    0x1000,
    0x800,
    0x400,
    0x200,
    0x100,
    0x80,
    0x40,
    0x20,
    0x10,
    0x8,
    0x4,
    0x2,
    0x1,
  ];

  static const _totrot = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

  /// Permutation and translation tables for DES
  static const _pc1 = [
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    0,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    27,
    19,
    11,
    3,
  ];

  /// Permuted choice key (table 2)
  static final _pc2 = [
    13,
    16,
    10,
    23,
    0,
    4,
    2,
    27,
    14,
    5,
    20,
    9,
    22,
    18,
    11,
    3,
    25,
    7,
    15,
    6,
    26,
    19,
    12,
    1,
    40,
    51,
    30,
    36,
    46,
    54,
    29,
    39,
    50,
    44,
    32,
    47,
    43,
    48,
    38,
    55,
    33,
    52,
    45,
    41,
    49,
    35,
    28,
    31,
  ];

  static const _sbox1 = [
    0x00808200,
    0x00000000,
    0x00008000,
    0x00808202,
    0x00808002,
    0x00008202,
    0x00000002,
    0x00008000,
    0x00000200,
    0x00808200,
    0x00808202,
    0x00000200,
    0x00800202,
    0x00808002,
    0x00800000,
    0x00000002,
    0x00000202,
    0x00800200,
    0x00800200,
    0x00008200,
    0x00008200,
    0x00808000,
    0x00808000,
    0x00800202,
    0x00008002,
    0x00800002,
    0x00800002,
    0x00008002,
    0x00000000,
    0x00000202,
    0x00008202,
    0x00800000,
    0x00008000,
    0x00808202,
    0x00000002,
    0x00808000,
    0x00808200,
    0x00800000,
    0x00800000,
    0x00000200,
    0x00808002,
    0x00008000,
    0x00008200,
    0x00800002,
    0x00000200,
    0x00000002,
    0x00800202,
    0x00008202,
    0x00808202,
    0x00008002,
    0x00808000,
    0x00800202,
    0x00800002,
    0x00000202,
    0x00008202,
    0x00808200,
    0x00000202,
    0x00800200,
    0x00800200,
    0x00000000,
    0x00008002,
    0x00008200,
    0x00000000,
    0x00808002,
  ];

  static const _sbox2 = [
    0x40084010,
    0x40004000,
    0x00004000,
    0x00084010,
    0x00080000,
    0x00000010,
    0x40080010,
    0x40004010,
    0x40000010,
    0x40084010,
    0x40084000,
    0x40000000,
    0x40004000,
    0x00080000,
    0x00000010,
    0x40080010,
    0x00084000,
    0x00080010,
    0x40004010,
    0x00000000,
    0x40000000,
    0x00004000,
    0x00084010,
    0x40080000,
    0x00080010,
    0x40000010,
    0x00000000,
    0x00084000,
    0x00004010,
    0x40084000,
    0x40080000,
    0x00004010,
    0x00000000,
    0x00084010,
    0x40080010,
    0x00080000,
    0x40004010,
    0x40080000,
    0x40084000,
    0x00004000,
    0x40080000,
    0x40004000,
    0x00000010,
    0x40084010,
    0x00084010,
    0x00000010,
    0x00004000,
    0x40000000,
    0x00004010,
    0x40084000,
    0x00080000,
    0x40000010,
    0x00080010,
    0x40004010,
    0x40000010,
    0x00080010,
    0x00084000,
    0x00000000,
    0x40004000,
    0x00004010,
    0x40000000,
    0x40080010,
    0x40084010,
    0x00084000,
  ];

  static const _sbox3 = [
    0x00000104,
    0x04010100,
    0x00000000,
    0x04010004,
    0x04000100,
    0x00000000,
    0x00010104,
    0x04000100,
    0x00010004,
    0x04000004,
    0x04000004,
    0x00010000,
    0x04010104,
    0x00010004,
    0x04010000,
    0x00000104,
    0x04000000,
    0x00000004,
    0x04010100,
    0x00000100,
    0x00010100,
    0x04010000,
    0x04010004,
    0x00010104,
    0x04000104,
    0x00010100,
    0x00010000,
    0x04000104,
    0x00000004,
    0x04010104,
    0x00000100,
    0x04000000,
    0x04010100,
    0x04000000,
    0x00010004,
    0x00000104,
    0x00010000,
    0x04010100,
    0x04000100,
    0x00000000,
    0x00000100,
    0x00010004,
    0x04010104,
    0x04000100,
    0x04000004,
    0x00000100,
    0x00000000,
    0x04010004,
    0x04000104,
    0x00010000,
    0x04000000,
    0x04010104,
    0x00000004,
    0x00010104,
    0x00010100,
    0x04000004,
    0x04010000,
    0x04000104,
    0x00000104,
    0x04010000,
    0x00010104,
    0x00000004,
    0x04010004,
    0x00010100,
  ];

  static const _sbox4 = [
    0x80401000,
    0x80001040,
    0x80001040,
    0x00000040,
    0x00401040,
    0x80400040,
    0x80400000,
    0x80001000,
    0x00000000,
    0x00401000,
    0x00401000,
    0x80401040,
    0x80000040,
    0x00000000,
    0x00400040,
    0x80400000,
    0x80000000,
    0x00001000,
    0x00400000,
    0x80401000,
    0x00000040,
    0x00400000,
    0x80001000,
    0x00001040,
    0x80400040,
    0x80000000,
    0x00001040,
    0x00400040,
    0x00001000,
    0x00401040,
    0x80401040,
    0x80000040,
    0x00400040,
    0x80400000,
    0x00401000,
    0x80401040,
    0x80000040,
    0x00000000,
    0x00000000,
    0x00401000,
    0x00001040,
    0x00400040,
    0x80400040,
    0x80000000,
    0x80401000,
    0x80001040,
    0x80001040,
    0x00000040,
    0x80401040,
    0x80000040,
    0x80000000,
    0x00001000,
    0x80400000,
    0x80001000,
    0x00401040,
    0x80400040,
    0x80001000,
    0x00001040,
    0x00400000,
    0x80401000,
    0x00000040,
    0x00400000,
    0x00001000,
    0x00401040,
  ];

  static const _sbox5 = [
    0x00000080,
    0x01040080,
    0x01040000,
    0x21000080,
    0x00040000,
    0x00000080,
    0x20000000,
    0x01040000,
    0x20040080,
    0x00040000,
    0x01000080,
    0x20040080,
    0x21000080,
    0x21040000,
    0x00040080,
    0x20000000,
    0x01000000,
    0x20040000,
    0x20040000,
    0x00000000,
    0x20000080,
    0x21040080,
    0x21040080,
    0x01000080,
    0x21040000,
    0x20000080,
    0x00000000,
    0x21000000,
    0x01040080,
    0x01000000,
    0x21000000,
    0x00040080,
    0x00040000,
    0x21000080,
    0x00000080,
    0x01000000,
    0x20000000,
    0x01040000,
    0x21000080,
    0x20040080,
    0x01000080,
    0x20000000,
    0x21040000,
    0x01040080,
    0x20040080,
    0x00000080,
    0x01000000,
    0x21040000,
    0x21040080,
    0x00040080,
    0x21000000,
    0x21040080,
    0x01040000,
    0x00000000,
    0x20040000,
    0x21000000,
    0x00040080,
    0x01000080,
    0x20000080,
    0x00040000,
    0x00000000,
    0x20040000,
    0x01040080,
    0x20000080,
  ];

  static const _sbox6 = [
    0x10000008,
    0x10200000,
    0x00002000,
    0x10202008,
    0x10200000,
    0x00000008,
    0x10202008,
    0x00200000,
    0x10002000,
    0x00202008,
    0x00200000,
    0x10000008,
    0x00200008,
    0x10002000,
    0x10000000,
    0x00002008,
    0x00000000,
    0x00200008,
    0x10002008,
    0x00002000,
    0x00202000,
    0x10002008,
    0x00000008,
    0x10200008,
    0x10200008,
    0x00000000,
    0x00202008,
    0x10202000,
    0x00002008,
    0x00202000,
    0x10202000,
    0x10000000,
    0x10002000,
    0x00000008,
    0x10200008,
    0x00202000,
    0x10202008,
    0x00200000,
    0x00002008,
    0x10000008,
    0x00200000,
    0x10002000,
    0x10000000,
    0x00002008,
    0x10000008,
    0x10202008,
    0x00202000,
    0x10200000,
    0x00202008,
    0x10202000,
    0x00000000,
    0x10200008,
    0x00000008,
    0x00002000,
    0x10200000,
    0x00202008,
    0x00002000,
    0x00200008,
    0x10002008,
    0x00000000,
    0x10202000,
    0x10000000,
    0x00200008,
    0x10002008,
  ];

  static const _sbox7 = [
    0x00100000,
    0x02100001,
    0x02000401,
    0x00000000,
    0x00000400,
    0x02000401,
    0x00100401,
    0x02100400,
    0x02100401,
    0x00100000,
    0x00000000,
    0x02000001,
    0x00000001,
    0x02000000,
    0x02100001,
    0x00000401,
    0x02000400,
    0x00100401,
    0x00100001,
    0x02000400,
    0x02000001,
    0x02100000,
    0x02100400,
    0x00100001,
    0x02100000,
    0x00000400,
    0x00000401,
    0x02100401,
    0x00100400,
    0x00000001,
    0x02000000,
    0x00100400,
    0x02000000,
    0x00100400,
    0x00100000,
    0x02000401,
    0x02000401,
    0x02100001,
    0x02100001,
    0x00000001,
    0x00100001,
    0x02000000,
    0x02000400,
    0x00100000,
    0x02100400,
    0x00000401,
    0x00100401,
    0x02100400,
    0x00000401,
    0x02000001,
    0x02100401,
    0x02100000,
    0x00100400,
    0x00000000,
    0x00000001,
    0x02100401,
    0x00000000,
    0x00100401,
    0x02100000,
    0x00000400,
    0x02000001,
    0x02000400,
    0x00000400,
    0x00100001,
  ];

  static const _sbox8 = [
    0x08000820,
    0x00000800,
    0x00020000,
    0x08020820,
    0x08000000,
    0x08000820,
    0x00000020,
    0x08000000,
    0x00020020,
    0x08020000,
    0x08020820,
    0x00020800,
    0x08020800,
    0x00020820,
    0x00000800,
    0x00000020,
    0x08020000,
    0x08000020,
    0x08000800,
    0x00000820,
    0x00020800,
    0x00020020,
    0x08020020,
    0x08020800,
    0x00000820,
    0x00000000,
    0x00000000,
    0x08020020,
    0x08000020,
    0x08000800,
    0x00020820,
    0x00020000,
    0x00020820,
    0x00020000,
    0x08020800,
    0x00000800,
    0x00000020,
    0x08020020,
    0x00000800,
    0x00020820,
    0x08000800,
    0x00000020,
    0x08000020,
    0x08020000,
    0x08020020,
    0x08000000,
    0x00020000,
    0x08000820,
    0x00000000,
    0x08020820,
    0x00020020,
    0x08000020,
    0x08020000,
    0x08000800,
    0x08000820,
    0x00000000,
    0x08020820,
    0x00020800,
    0x00020800,
    0x00000820,
    0x00000820,
    0x00020020,
    0x08000000,
    0x08020800,
  ];

  static const _blockSize = 8;

  List<int> _workingKey = [];

  @override
  String get algorithmName => 'DES';

  @override
  int get blockSize => _blockSize;

  @override
  void init(final bool forEncryption, final CipherParameters? params) {
    if (params is KeyParameter) {
      if (params.key.length > 8) {
        throw ArgumentError('DES key too long - should be 8 bytes');
      }
      _workingKey = generateWorkingKey(forEncryption, params.key);
    } else {
      throw ArgumentError('Invalid parameter passed to $algorithmName init - ${params.runtimeType}');
    }
  }

  @override
  int processBlock(final Uint8List input, final int inOff, final Uint8List output, final int outOff) {
    if (_workingKey.isEmpty) {
      throw StateError('$algorithmName engine not initialised');
    }
    if ((inOff + _blockSize) > input.lengthInBytes) {
      throw ArgumentError('input buffer too short for $algorithmName engine');
    }

    if ((outOff + _blockSize) > output.lengthInBytes) {
      throw ArgumentError('output buffer too short for $algorithmName engine');
    }

    desFunc(_workingKey, input, inOff, output, outOff);
    return _blockSize;
  }

  @override
  void reset() {}

  List<int> generateWorkingKey(final bool forEncryption, final Uint8List key) {
    final newKey = List<int>.generate(32, (_) => 0, growable: false);
    final pc1m = List<bool>.generate(56, (_) => false, growable: false);
    final pcr = List<bool>.generate(56, (_) => false, growable: false);

    for (var j = 0; j < 56; j++) {
      final l = _pc1[j];
      pc1m[j] = ((key[l >> 3] & _bytebit[l & 07]) != 0);
    }

    for (var i = 0; i < 16; i++) {
      final m = forEncryption ? i << 1 : (15 - i) << 1;
      final n = m + 1;
      newKey[m] = newKey[n] = 0;

      for (var j = 0; j < 28; j++) {
        final l = j + _totrot[i];
        if (l < 28) {
          pcr[j] = pc1m[l];
        } else {
          pcr[j] = pc1m[l - 28];
        }
      }

      for (var j = 28; j < 56; j++) {
        final l = j + _totrot[i];
        if (l < 56) {
          pcr[j] = pc1m[l];
        } else {
          pcr[j] = pc1m[l - 28];
        }
      }

      for (var j = 0; j < 24; j++) {
        if (pcr[_pc2[j]]) {
          newKey[m] |= _bigbyte[j];
        }

        if (pcr[_pc2[j + 24]]) {
          newKey[n] |= _bigbyte[j];
        }
      }
    }

    /// store the processed key
    for (var i = 0; i != 32; i += 2) {
      final i1 = newKey[i];
      final i2 = newKey[i + 1];

      newKey[i] =
          ((i1 & 0x00fc0000) << 6) | ((i1 & 0x00000fc0) << 10) | ((i2 & 0x00fc0000) >> 10) | ((i2 & 0x00000fc0) >> 6);

      newKey[i + 1] =
          ((i1 & 0x0003f000) << 12) | ((i1 & 0x0000003f) << 16) | ((i2 & 0x0003f000) >> 4) | (i2 & 0x0000003f);
    }

    return newKey;
  }

  void desFunc(
    final List<int> workingKey,
    final Uint8List input,
    final int inOff,
    final Uint8List output,
    final int outOff,
  ) {
    int work;
    var left = input.sublist(inOff, inOff + 4).toUint32();
    var right = input.sublist(inOff + 4, inOff + 8).toUint32();

    /// Initial IP permutation.
    work = ((left >> 4) ^ right) & 0x0f0f0f0f;
    right ^= work;
    left ^= (work << 4);

    work = ((left >> 16) ^ right) & 0x0000ffff;
    right ^= work;
    left ^= (work << 16);

    work = ((right >> 2) ^ left) & 0x33333333;
    left ^= work;
    right ^= (work << 2);

    work = ((right >> 8) ^ left) & 0x00ff00ff;
    left ^= work;
    right ^= (work << 8);

    work = ((left >> 1) ^ right) & 0x55555555;
    right ^= work;
    left ^= work << 1;

    /// Perform the 16 steps.
    var ki = 0;
    for (var i = 0; i < 16; i++) {
      /// Feistel (F) function
      final b1 = ((right >> 3) & 0x1fffffff) ^ (right << 29) ^ workingKey[ki++];
      final b2 = ((right >> 31) & 0x00000001) ^ (right << 1) ^ workingKey[ki++];

      work = _sbox1[(b1 >> 24) & 0x3f] ^
          _sbox2[(b2 >> 24) & 0x3f] ^
          _sbox3[(b1 >> 16) & 0x3f] ^
          _sbox4[(b2 >> 16) & 0x3f] ^
          _sbox5[(b1 >> 8) & 0x3f] ^
          _sbox6[(b2 >> 8) & 0x3f] ^
          _sbox7[b1 & 0x3f] ^
          _sbox8[b2 & 0x3f] ^
          left;

      left = right;
      right = work;
    }

    /// Last step should not permute L & R.
    work = left;
    left = right;
    right = work;

    /// Final IP permutation
    work = ((left >> 1) ^ right) & 0x55555555;
    right ^= work;
    left ^= work << 1;

    work = ((right >> 8) ^ left) & 0x00ff00ff;
    left ^= work;
    right ^= (work << 8);

    work = ((right >> 2) ^ left) & 0x33333333;
    left ^= work;
    right ^= (work << 2);

    work = ((left >> 16) ^ right) & 0x0000ffff;
    right ^= work;
    left ^= (work << 16);

    work = ((left >> 4) ^ right) & 0x0f0f0f0f;
    right ^= work;
    left ^= (work << 4);

    output.setRange(outOff, outOff + _blockSize, [...left.unpack32(), ...right.unpack32()]);
  }
}
