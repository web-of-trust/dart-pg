// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/helpers.dart';
import 'package:pointycastle/api.dart';

/// An implementation of the Key Wrapper from the NIST Key Wrap
/// Specification as described in RFC 3394.
class Rfc3394WrapEngine {
  final _iv = Uint8List.fromList([
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
  ]);

  final BlockCipher _engine;

  late KeyParameter _param;

  late bool _forWrapping;

  Rfc3394WrapEngine(this._engine);

  String get algorithmName => _engine.algorithmName;

  void init(final bool forWrapping, final CipherParameters params) {
    _forWrapping = forWrapping;
    if (params is KeyParameter) {
      _param = params;
    } else if (params is ParametersWithIV) {
      _iv.setAll(0, params.iv.sublist(0, _iv.length));
      _param = params.parameters as KeyParameter;
    } else {
      throw ArgumentError('Invalid parameter passed to $algorithmName init - ${params.runtimeType}');
    }
  }

  Uint8List wrap(Uint8List input, int inOffset, int inLength) {
    if (!_forWrapping) {
      throw StateError('not set for wrapping');
    }
    final n = inLength ~/ 8;

    if ((n * 8) != inLength) {
      throw StateError('wrap data must be a multiple of 8 bytes');
    }

    final block = Uint8List(inLength + _iv.length)
      ..setAll(0, _iv)
      ..setAll(_iv.length, input.sublist(inOffset, inOffset + inLength));
    final buffer = Uint8List(8 + _iv.length);
    _engine.init(_forWrapping, _param);

    for (var j = 0; j != 6; j++) {
      for (var i = 1; i <= n; i++) {
        buffer.setAll(0, block.sublist(0, _iv.length));
        buffer.setAll(_iv.length, block.sublist(8 * i, (8 * i) + 8));
        _engine.processBlock(buffer, 0, buffer, 0);

        var t = n * j + i;
        for (var k = 1; t != 0; k++) {
          final v = t & 0xff;
          buffer[_iv.length - k] ^= v;
          t = t >> 8;
        }
        block.setAll(0, buffer.sublist(0, 8));
        block.setAll(8 * i, buffer.sublist(8, 16));
      }
    }
    return block;
  }

  Uint8List unwrap(Uint8List input, int inOffset, int inLength) {
    if (_forWrapping) {
      throw StateError('not set for unwrapping');
    }
    var n = inLength ~/ 8;

    if ((n * 8) != inLength) {
      throw StateError('unwrap data must be a multiple of 8 bytes');
    }

    final a = Uint8List(_iv.length)..setAll(0, input.sublist(inOffset, inOffset + _iv.length));
    final block = Uint8List(inLength - _iv.length)
      ..setAll(0, input.sublist(inOffset + _iv.length, inOffset + inLength));
    final buffer = Uint8List(8 + _iv.length);

    _engine.init(_forWrapping, _param);
    n = n - 1;

    for (var j = 5; j >= 0; j--) {
      for (var i = n; i >= 1; i--) {
        buffer.setAll(0, a.sublist(0, _iv.length));
        buffer.setAll(_iv.length, block.sublist(8 * (i - 1), 8 * (i - 1) + 8));

        var t = n * j + i;
        for (var k = 1; t != 0; k++) {
          final v = t & 0xff;
          buffer[_iv.length - k] ^= v;
          t = t >> 8;
        }
        _engine.processBlock(buffer, 0, buffer, 0);
        a.setAll(0, buffer.sublist(0, 8));
        block.setAll(8 * (i - 1), buffer.sublist(8, 16));
      }
    }

    if (!_iv.equals(a)) {
      throw StateError('checksum failed');
    }
    return block;
  }
}
