/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import 'base_engine.dart';
import '../../common/extensions.dart';

/// A class that provides a basic International Data Encryption Algorithm (IDEA) engine.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class IDEAEngine extends BaseEngine {
  static const _mask = 0xffff;
  static const _base = 0x10001;

  static const _blockSize = 8;

  late List<int> _workingKey;

  @override
  String get algorithmName => 'IDEA';

  @override
  int get blockSize => _blockSize;

  @override
  void init(final bool forEncryption, final CipherParameters? params) {
    if (params is KeyParameter) {
      _workingKey = _generateWorkingKey(forEncryption, params.key);
    } else {
      throw ArgumentError(
        'Invalid parameter passed to $algorithmName init - ${params.runtimeType}',
      );
    }
  }

  @override
  int processBlock(
    final Uint8List input,
    final int inOff,
    final Uint8List output,
    final int outOff,
  ) {
    if (_workingKey.isEmpty) {
      throw StateError('$algorithmName not initialised');
    }
    if ((inOff + _blockSize) > input.length) {
      throw ArgumentError('input buffer too short for $algorithmName engine');
    }
    if ((outOff + _blockSize) > output.length) {
      throw ArgumentError('output buffer too short for $algorithmName engine');
    }

    _ideaFunc(_workingKey, input, inOff, output, outOff);

    return _blockSize;
  }

  List<int> _generateWorkingKey(final bool forEncryption, final Uint8List key) {
    if (forEncryption) {
      return _expandKey(key);
    } else {
      return _invertKey(_expandKey(key));
    }
  }

  List<int> _expandKey(final Uint8List uKey) {
    final Uint8List tmpKey;
    if (uKey.length < 16) {
      tmpKey = Uint8List(16);
      tmpKey.setAll(tmpKey.length - uKey.length, uKey.sublist(0));
    } else {
      tmpKey = uKey;
    }

    final key = List.filled(52, 0);
    for (var i = 0; i < 8; i++) {
      key[i] = _unpack16(tmpKey.sublist(i * 2));
    }
    for (var i = 8; i < 52; i++) {
      if ((i & 7) < 6) {
        key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & _mask;
      } else if ((i & 7) == 6) {
        key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & _mask;
      } else {
        key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & _mask;
      }
    }
    return key;
  }

  List<int> _invertKey(final List<int> inKey) {
    var p = 52;
    var inOff = 0;
    final key = List.filled(p, 0);

    var t1 = _mulInv(inKey[inOff++]);
    var t2 = _addInv(inKey[inOff++]);
    var t3 = _addInv(inKey[inOff++]);
    var t4 = _mulInv(inKey[inOff++]);
    key[--p] = t4;
    key[--p] = t3;
    key[--p] = t2;
    key[--p] = t1;

    for (var round = 1; round < 8; round++) {
      t1 = inKey[inOff++];
      t2 = inKey[inOff++];
      key[--p] = t2;
      key[--p] = t1;

      t1 = _mulInv(inKey[inOff++]);
      t2 = _addInv(inKey[inOff++]);
      t3 = _addInv(inKey[inOff++]);
      t4 = _mulInv(inKey[inOff++]);
      key[--p] = t4;
      key[--p] = t2;
      key[--p] = t3;
      key[--p] = t1;
    }

    t1 = inKey[inOff++];
    t2 = inKey[inOff++];
    key[--p] = t2;
    key[--p] = t1;

    t1 = _mulInv(inKey[inOff++]);
    t2 = _addInv(inKey[inOff++]);
    t3 = _addInv(inKey[inOff++]);
    t4 = _mulInv(inKey[inOff]);
    key[--p] = t4;
    key[--p] = t3;
    key[--p] = t2;
    key[--p] = t1;

    return key;
  }

  void _ideaFunc(
    final List<int> workingKey,
    final Uint8List input,
    final int inOff,
    final Uint8List output,
    final int outOff,
  ) {
    var x0 = _unpack16(input.sublist(inOff));
    var x1 = _unpack16(input.sublist(inOff + 2));
    var x2 = _unpack16(input.sublist(inOff + 4));
    var x3 = _unpack16(input.sublist(inOff + 6));

    var keyOff = 0;
    for (var round = 0; round < 8; round++) {
      x0 = _mul(x0, workingKey[keyOff++]);
      x1 += workingKey[keyOff++];
      x1 &= _mask;
      x2 += workingKey[keyOff++];
      x2 &= _mask;
      x3 = _mul(x3, workingKey[keyOff++]);

      final t0 = x1;
      final t1 = x2;
      x2 ^= x0;
      x1 ^= x3;

      x2 = _mul(x2, workingKey[keyOff++]);
      x1 += x2;
      x1 &= _mask;

      x1 = _mul(x1, workingKey[keyOff++]);
      x2 += x1;
      x2 &= _mask;

      x0 ^= x1;
      x3 ^= x2;
      x1 ^= t1;
      x2 ^= t0;
    }

    output.setAll(outOff, _pack16(_mul(x0, workingKey[keyOff++])));
    output.setAll(outOff + 2, _pack16(x2 + workingKey[keyOff++]));
    output.setAll(outOff + 4, _pack16(x1 + workingKey[keyOff++]));
    output.setAll(outOff + 6, _pack16(_mul(x3, workingKey[keyOff])));
  }

  int _mulInv(int x) {
    if (x < 2) {
      return x;
    }
    int t0, t1, q, y;

    t0 = 1;
    t1 = _base ~/ x;
    y = _base % x;

    while (y != 1) {
      q = x ~/ y;
      x = x % y;
      t0 = (t0 + (t1 * q)) & _mask;
      if (x == 1) {
        return t0;
      }
      q = y ~/ x;
      y = y % x;
      t1 = (t1 + (t0 * q)) & _mask;
    }

    return (1 - t1) & _mask;
  }

  int _addInv(int x) {
    return (0 - x) & _mask;
  }

  int _mul(int x, int y) {
    if (x == 0) {
      x = (_base - y);
    } else if (y == 0) {
      x = (_base - x);
    } else {
      final p = x * y;

      y = p & _mask;
      x = p >> 16;
      x = y - x + ((y < x) ? 1 : 0);
    }

    return x & _mask;
  }

  static int _unpack16(final Uint8List x) => x.unpack16();
  static Uint8List _pack16(final int x) => x.pack16();
}
