// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/api.dart';

import 'dart:typed_data';

import '../../byte_utils.dart';
import 'base_cipher.dart';

/// A class that provides a basic DES engine.
class DESEngine extends BaseCipher {
  static const _bytebit = [0200, 0100, 040, 020, 010, 04, 02, 01];

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

  static const _totrot = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

  static const _pc2 = [
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

  static final _sp1 = [
    0x01010400,
    0x00000000,
    0x00010000,
    0x01010404,
    0x01010004,
    0x00010404,
    0x00000004,
    0x00010000,
    0x00000400,
    0x01010400,
    0x01010404,
    0x00000400,
    0x01000404,
    0x01010004,
    0x01000000,
    0x00000004,
    0x00000404,
    0x01000400,
    0x01000400,
    0x00010400,
    0x00010400,
    0x01010000,
    0x01010000,
    0x01000404,
    0x00010004,
    0x01000004,
    0x01000004,
    0x00010004,
    0x00000000,
    0x00000404,
    0x00010404,
    0x01000000,
    0x00010000,
    0x01010404,
    0x00000004,
    0x01010000,
    0x01010400,
    0x01000000,
    0x01000000,
    0x00000400,
    0x01010004,
    0x00010000,
    0x00010400,
    0x01000004,
    0x00000400,
    0x00000004,
    0x01000404,
    0x00010404,
    0x01010404,
    0x00010004,
    0x01010000,
    0x01000404,
    0x01000004,
    0x00000404,
    0x00010404,
    0x01010400,
    0x00000404,
    0x01000400,
    0x01000400,
    0x00000000,
    0x00010004,
    0x00010400,
    0x00000000,
    0x01010004,
  ];

  static const _sp2 = [
    0x80108020,
    0x80008000,
    0x00008000,
    0x00108020,
    0x00100000,
    0x00000020,
    0x80100020,
    0x80008020,
    0x80000020,
    0x80108020,
    0x80108000,
    0x80000000,
    0x80008000,
    0x00100000,
    0x00000020,
    0x80100020,
    0x00108000,
    0x00100020,
    0x80008020,
    0x00000000,
    0x80000000,
    0x00008000,
    0x00108020,
    0x80100000,
    0x00100020,
    0x80000020,
    0x00000000,
    0x00108000,
    0x00008020,
    0x80108000,
    0x80100000,
    0x00008020,
    0x00000000,
    0x00108020,
    0x80100020,
    0x00100000,
    0x80008020,
    0x80100000,
    0x80108000,
    0x00008000,
    0x80100000,
    0x80008000,
    0x00000020,
    0x80108020,
    0x00108020,
    0x00000020,
    0x00008000,
    0x80000000,
    0x00008020,
    0x80108000,
    0x00100000,
    0x80000020,
    0x00100020,
    0x80008020,
    0x80000020,
    0x00100020,
    0x00108000,
    0x00000000,
    0x80008000,
    0x00008020,
    0x80000000,
    0x80100020,
    0x80108020,
    0x00108000,
  ];

  static const _sp3 = [
    0x00000208,
    0x08020200,
    0x00000000,
    0x08020008,
    0x08000200,
    0x00000000,
    0x00020208,
    0x08000200,
    0x00020008,
    0x08000008,
    0x08000008,
    0x00020000,
    0x08020208,
    0x00020008,
    0x08020000,
    0x00000208,
    0x08000000,
    0x00000008,
    0x08020200,
    0x00000200,
    0x00020200,
    0x08020000,
    0x08020008,
    0x00020208,
    0x08000208,
    0x00020200,
    0x00020000,
    0x08000208,
    0x00000008,
    0x08020208,
    0x00000200,
    0x08000000,
    0x08020200,
    0x08000000,
    0x00020008,
    0x00000208,
    0x00020000,
    0x08020200,
    0x08000200,
    0x00000000,
    0x00000200,
    0x00020008,
    0x08020208,
    0x08000200,
    0x08000008,
    0x00000200,
    0x00000000,
    0x08020008,
    0x08000208,
    0x00020000,
    0x08000000,
    0x08020208,
    0x00000008,
    0x00020208,
    0x00020200,
    0x08000008,
    0x08020000,
    0x08000208,
    0x00000208,
    0x08020000,
    0x00020208,
    0x00000008,
    0x08020008,
    0x00020200,
  ];

  static const _sp4 = [
    0x00802001,
    0x00002081,
    0x00002081,
    0x00000080,
    0x00802080,
    0x00800081,
    0x00800001,
    0x00002001,
    0x00000000,
    0x00802000,
    0x00802000,
    0x00802081,
    0x00000081,
    0x00000000,
    0x00800080,
    0x00800001,
    0x00000001,
    0x00002000,
    0x00800000,
    0x00802001,
    0x00000080,
    0x00800000,
    0x00002001,
    0x00002080,
    0x00800081,
    0x00000001,
    0x00002080,
    0x00800080,
    0x00002000,
    0x00802080,
    0x00802081,
    0x00000081,
    0x00800080,
    0x00800001,
    0x00802000,
    0x00802081,
    0x00000081,
    0x00000000,
    0x00000000,
    0x00802000,
    0x00002080,
    0x00800080,
    0x00800081,
    0x00000001,
    0x00802001,
    0x00002081,
    0x00002081,
    0x00000080,
    0x00802081,
    0x00000081,
    0x00000001,
    0x00002000,
    0x00800001,
    0x00002001,
    0x00802080,
    0x00800081,
    0x00002001,
    0x00002080,
    0x00800000,
    0x00802001,
    0x00000080,
    0x00800000,
    0x00002000,
    0x00802080,
  ];

  static const _sp5 = [
    0x00000100,
    0x02080100,
    0x02080000,
    0x42000100,
    0x00080000,
    0x00000100,
    0x40000000,
    0x02080000,
    0x40080100,
    0x00080000,
    0x02000100,
    0x40080100,
    0x42000100,
    0x42080000,
    0x00080100,
    0x40000000,
    0x02000000,
    0x40080000,
    0x40080000,
    0x00000000,
    0x40000100,
    0x42080100,
    0x42080100,
    0x02000100,
    0x42080000,
    0x40000100,
    0x00000000,
    0x42000000,
    0x02080100,
    0x02000000,
    0x42000000,
    0x00080100,
    0x00080000,
    0x42000100,
    0x00000100,
    0x02000000,
    0x40000000,
    0x02080000,
    0x42000100,
    0x40080100,
    0x02000100,
    0x40000000,
    0x42080000,
    0x02080100,
    0x40080100,
    0x00000100,
    0x02000000,
    0x42080000,
    0x42080100,
    0x00080100,
    0x42000000,
    0x42080100,
    0x02080000,
    0x00000000,
    0x40080000,
    0x42000000,
    0x00080100,
    0x02000100,
    0x40000100,
    0x00080000,
    0x00000000,
    0x40080000,
    0x02080100,
    0x40000100,
  ];

  static const _sp6 = [
    0x20000010,
    0x20400000,
    0x00004000,
    0x20404010,
    0x20400000,
    0x00000010,
    0x20404010,
    0x00400000,
    0x20004000,
    0x00404010,
    0x00400000,
    0x20000010,
    0x00400010,
    0x20004000,
    0x20000000,
    0x00004010,
    0x00000000,
    0x00400010,
    0x20004010,
    0x00004000,
    0x00404000,
    0x20004010,
    0x00000010,
    0x20400010,
    0x20400010,
    0x00000000,
    0x00404010,
    0x20404000,
    0x00004010,
    0x00404000,
    0x20404000,
    0x20000000,
    0x20004000,
    0x00000010,
    0x20400010,
    0x00404000,
    0x20404010,
    0x00400000,
    0x00004010,
    0x20000010,
    0x00400000,
    0x20004000,
    0x20000000,
    0x00004010,
    0x20000010,
    0x20404010,
    0x00404000,
    0x20400000,
    0x00404010,
    0x20404000,
    0x00000000,
    0x20400010,
    0x00000010,
    0x00004000,
    0x20400000,
    0x00404010,
    0x00004000,
    0x00400010,
    0x20004010,
    0x00000000,
    0x20404000,
    0x20000000,
    0x00400010,
    0x20004010,
  ];

  static const _sp7 = [
    0x00200000,
    0x04200002,
    0x04000802,
    0x00000000,
    0x00000800,
    0x04000802,
    0x00200802,
    0x04200800,
    0x04200802,
    0x00200000,
    0x00000000,
    0x04000002,
    0x00000002,
    0x04000000,
    0x04200002,
    0x00000802,
    0x04000800,
    0x00200802,
    0x00200002,
    0x04000800,
    0x04000002,
    0x04200000,
    0x04200800,
    0x00200002,
    0x04200000,
    0x00000800,
    0x00000802,
    0x04200802,
    0x00200800,
    0x00000002,
    0x04000000,
    0x00200800,
    0x04000000,
    0x00200800,
    0x00200000,
    0x04000802,
    0x04000802,
    0x04200002,
    0x04200002,
    0x00000002,
    0x00200002,
    0x04000000,
    0x04000800,
    0x00200000,
    0x04200800,
    0x00000802,
    0x00200802,
    0x04200800,
    0x00000802,
    0x04000002,
    0x04200802,
    0x04200000,
    0x00200800,
    0x00000000,
    0x00000002,
    0x04200802,
    0x00000000,
    0x00200802,
    0x04200000,
    0x00000800,
    0x04000002,
    0x04000800,
    0x00000800,
    0x00200002,
  ];

  static const _sp8 = [
    0x10001040,
    0x00001000,
    0x00040000,
    0x10041040,
    0x10000000,
    0x10001040,
    0x00000040,
    0x10000000,
    0x00040040,
    0x10040000,
    0x10041040,
    0x00041000,
    0x10041000,
    0x00041040,
    0x00001000,
    0x00000040,
    0x10040000,
    0x10000040,
    0x10001000,
    0x00001040,
    0x00041000,
    0x00040040,
    0x10040040,
    0x10041000,
    0x00001040,
    0x00000000,
    0x00000000,
    0x10040040,
    0x10000040,
    0x10001000,
    0x00041040,
    0x00040000,
    0x00041040,
    0x00040000,
    0x10041000,
    0x00001000,
    0x00000040,
    0x10040040,
    0x00001000,
    0x00041040,
    0x10001000,
    0x00000040,
    0x10000040,
    0x10040000,
    0x10040040,
    0x10000000,
    0x00040000,
    0x10001040,
    0x00000000,
    0x10041040,
    0x00040040,
    0x10000040,
    0x10040000,
    0x10001000,
    0x10001040,
    0x00000000,
    0x10041040,
    0x00041000,
    0x00041000,
    0x00001040,
    0x00001040,
    0x00040040,
    0x10000000,
    0x10041000,
  ];

  static const _blockSize = 8;

  late Uint8List _workingKey;

  @override
  String get algorithmName => 'DES';

  @override
  int get blockSize => _blockSize;

  @override
  void init(final bool forEncryption, final CipherParameters? params) {
    if (params is KeyParameter) {
      if ((params).key.length > 8) {
        throw ArgumentError('DES key too long - should be 8 bytes');
      }
      _workingKey = generateWorkingKey(forEncryption, params.key);
    } else {
      throw ArgumentError('Invalid parameter passed to $algorithmName init - ${params.runtimeType}');
    }
  }

  @override
  int processBlock(final Uint8List inp, final int inpOff, final Uint8List out, final int outOff) {
    if (_workingKey.isEmpty) {
      throw StateError('$algorithmName engine not initialised');
    }
    if ((inpOff + blockSize) > inp.length) {
      throw ArgumentError('input buffer too short');
    }

    if ((outOff + blockSize) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    desFunc(_workingKey, inp, inpOff, out, outOff);
    return blockSize;
  }

  @override
  void reset() {}

  Uint8List generateWorkingKey(final bool forEncryption, final Uint8List key) {
    final newKey = List.filled(32, 0);
    final pc1m = List.filled(56, false);
    final pcr = List.filled(56, false);

    for (var j = 0; j < 56; j++) {
      final l = _pc1[j];
      pc1m[j] = ((key[l >>> 3] & _bytebit[l & 07]) != 0);
    }

    for (var i = 0; i < 16; i++) {
      final m = forEncryption ? i << 1 : (15 - i) << 1;
      final n = m + 1;
      newKey[m] = newKey[n] = 0;

      int l;
      for (var j = 0; j < 28; j++) {
        l = j + _totrot[i];
        if (l < 28) {
          pcr[j] = pc1m[l];
        } else {
          pcr[j] = pc1m[l - 28];
        }
      }

      for (var j = 28; j < 56; j++) {
        l = j + _totrot[i];
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
          ((i1 & 0x00fc0000) << 6) | ((i1 & 0x00000fc0) << 10) | ((i2 & 0x00fc0000) >>> 10) | ((i2 & 0x00000fc0) >>> 6);

      newKey[i + 1] =
          ((i1 & 0x0003f000) << 12) | ((i1 & 0x0000003f) << 16) | ((i2 & 0x0003f000) >>> 4) | (i2 & 0x0000003f);
    }

    return Uint8List.fromList(newKey);
  }

  void desFunc(
    final Uint8List workingKey,
    final Uint8List inp,
    final int inpOff,
    final Uint8List out,
    final int outOff,
  ) {
    var left = ByteUtils.bytesToIn32(inp.sublist(inpOff));
    var right = ByteUtils.bytesToIn32(inp.sublist(inpOff + 4));

    var work = ((left >>> 4) ^ right) & 0x0f0f0f0f;
    right ^= work;
    left ^= (work << 4);
    work = ((left >>> 16) ^ right) & 0x0000ffff;
    right ^= work;
    left ^= (work << 16);
    work = ((right >>> 2) ^ left) & 0x33333333;
    left ^= work;
    right ^= (work << 2);
    work = ((right >>> 8) ^ left) & 0x00ff00ff;
    left ^= work;
    right ^= (work << 8);
    right = (right << 1) | (right >>> 31);
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = (left << 1) | (left >>> 31);

    for (var round = 0; round < 8; round++) {
      int fval;

      work = (right << 28) | (right >>> 4);
      work ^= workingKey[round * 4 + 0];
      fval = _sp7[work & 0x3f];
      fval |= _sp5[(work >>> 8) & 0x3f];
      fval |= _sp3[(work >>> 16) & 0x3f];
      fval |= _sp1[(work >>> 24) & 0x3f];
      work = right ^ workingKey[round * 4 + 1];
      fval |= _sp8[work & 0x3f];
      fval |= _sp6[(work >>> 8) & 0x3f];
      fval |= _sp4[(work >>> 16) & 0x3f];
      fval |= _sp2[(work >>> 24) & 0x3f];
      left ^= fval;
      work = (left << 28) | (left >>> 4);
      work ^= workingKey[round * 4 + 2];
      fval = _sp7[work & 0x3f];
      fval |= _sp5[(work >>> 8) & 0x3f];
      fval |= _sp3[(work >>> 16) & 0x3f];
      fval |= _sp1[(work >>> 24) & 0x3f];
      work = left ^ workingKey[round * 4 + 3];
      fval |= _sp8[work & 0x3f];
      fval |= _sp6[(work >>> 8) & 0x3f];
      fval |= _sp4[(work >>> 16) & 0x3f];
      fval |= _sp2[(work >>> 24) & 0x3f];
      right ^= fval;
    }

    right = (right << 31) | (right >>> 1);
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = (left << 31) | (left >>> 1);
    work = ((left >>> 8) ^ right) & 0x00ff00ff;
    right ^= work;
    left ^= (work << 8);
    work = ((left >>> 2) ^ right) & 0x33333333;
    right ^= work;
    left ^= (work << 2);
    work = ((right >>> 16) ^ left) & 0x0000ffff;
    left ^= work;
    right ^= (work << 16);
    work = ((right >>> 4) ^ left) & 0x0f0f0f0f;
    left ^= work;
    right ^= (work << 4);

    out.setAll(outOff, ByteUtils.int32Bytes(right));
    out.setAll(outOff + 4, ByteUtils.int32Bytes(left));
  }
}
