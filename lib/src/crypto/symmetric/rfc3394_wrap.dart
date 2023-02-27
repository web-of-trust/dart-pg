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

  Uint8List wrap(final Uint8List input, final int inOffset) {
    if (!_forWrapping) {
      throw StateError('not set for wrapping');
    }

    if (input.lengthInBytes < 16) {
      throw StateError('Wrap data to be wrapped should be at least 128 bits.');
    }

    if (input.lengthInBytes % 8 != 0) {
      throw StateError('Wrap data must be a multiple of 8 bytes');
    }

    final a = _iv;
    final r = input;
    final n = input.lengthInBytes ~/ 8;
    _engine.init(_forWrapping, _param);
    for (var j = 0; j <= 5; j++) {
      for (var i = 1; i <= n; i++) {
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        _engine.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        a[7] ^= (n * j + i) & 0xff;
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }
    return Uint8List.fromList([...a, ...r]);
  }

  Uint8List unwrap(final Uint8List input, final int inOffset) {
    if (_forWrapping) {
      throw StateError('not set for unwrapping');
    }
    if (input.lengthInBytes < 16) {
      throw StateError('Wrap data to be wrapped should be at least 128 bits.');
    }

    if (input.lengthInBytes % 8 != 0) {
      throw StateError('Wrap data must be a multiple of 8 bytes');
    }

    final a = input.sublist(0, 8);
    final r = input.sublist(8);
    final n = (input.lengthInBytes ~/ 8) - 1;
    _engine.init(_forWrapping, _param);
    for (var j = 5; j >= 0; j--) {
      for (var i = n; i >= 1; i--) {
        a[7] ^= (n * j + i) & 0xff;
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        _engine.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }
    if (!_iv.equals(a)) {
      throw StateError('Checksum failed');
    }

    return r;
  }
}
