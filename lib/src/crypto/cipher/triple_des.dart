// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/api.dart';

import 'dart:typed_data';

import 'des.dart';

class TripleDES extends DESEngine {
  static const _blockSize = 8;

  bool _forEncryption = false;

  late Uint8List _workingKey1;

  late Uint8List _workingKey2;

  late Uint8List _workingKey3;

  @override
  String get algorithmName => 'TripleDES';

  @override
  int get blockSize => _blockSize;

  @override
  void init(final bool forEncryption, final CipherParameters? params) {
    if (params is! KeyParameter) {
      throw ArgumentError('Invalid parameter passed to $algorithmName init - ${params.runtimeType}');
    }
    final keyMaster = params.key;
    if (keyMaster.length != 24 && keyMaster.length != 16) {
      throw ArgumentError('key size must be 16 or 24 bytes.');
    }

    _forEncryption = forEncryption;

    final key1 = Uint8List.fromList(keyMaster.sublist(0, 8));
    _workingKey1 = generateWorkingKey(forEncryption, key1);

    final key2 = Uint8List.fromList(keyMaster.sublist(8, 16));
    _workingKey2 = generateWorkingKey(!forEncryption, key2);
    if (keyMaster.length == 24) {
      final key3 = Uint8List.fromList(keyMaster.sublist(16, 24));
      _workingKey3 = generateWorkingKey(forEncryption, key3);
    } else {
      _workingKey3 = _workingKey1;
    }
  }

  @override
  int processBlock(final Uint8List inp, final int inpOff, final Uint8List out, final int outOff) {
    if (_workingKey1.isEmpty) {
      throw StateError('$algorithmName engine not initialised');
    }
    if ((inpOff + _blockSize) > inp.length) {
      throw ArgumentError('input buffer too short');
    }
    if ((outOff + _blockSize) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    final temp = Uint8List(_blockSize);

    if (_forEncryption) {
      desFunc(_workingKey1, inp, inpOff, temp, 0);
      desFunc(_workingKey2, temp, 0, temp, 0);
      desFunc(_workingKey3, temp, 0, out, outOff);
    } else {
      desFunc(_workingKey3, inp, inpOff, temp, 0);
      desFunc(_workingKey2, temp, 0, temp, 0);
      desFunc(_workingKey1, temp, 0, out, outOff);
    }
    return _blockSize;
  }

  @override
  void reset() {}
}
