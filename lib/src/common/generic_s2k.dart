/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'helpers.dart';
import '../enum/hash_algorithm.dart';
import '../enum/s2k_type.dart';
import '../type/s2k.dart';

/// Implementation of the string-to-key specifier
/// See https://www.rfc-editor.org/rfc/rfc9580#section-3.7
class GenericS2k implements S2kInterface {
  /// Default salt length
  static const saltLength = 8;

  /// Exponent bias
  static const _expbias = 6;

  /// Default iteration count byte
  static const _defaultItCount = 224;

  /// Hash function identifier
  final HashAlgorithm hash;

  /// s2k iteration count
  final int itCount;

  // s2k iteration count byte
  final int count;

  @override
  final Uint8List salt;

  @override
  final S2kType type;

  GenericS2k(
    this.salt, {
    this.type = S2kType.iterated,
    this.hash = HashAlgorithm.sha256,
    this.itCount = _defaultItCount,
  }) : count = (16 + (itCount & 15)) << ((itCount >> 4) + _expbias);

  /// Parsing function for a string-to-key specifier
  factory GenericS2k.fromBytes(final Uint8List bytes) {
    var pos = 0;
    final type = S2kType.values.firstWhere(
      (type) => type.value == bytes[pos],
    );
    pos++;
    final hash = HashAlgorithm.values.firstWhere(
      (hash) => hash.value == bytes[pos],
    );
    pos++;

    var itCount = 0;
    final Uint8List salt;
    switch (type) {
      case S2kType.salted:
        salt = bytes.sublist(pos, pos + saltLength);
        break;
      case S2kType.iterated:
        salt = bytes.sublist(pos, pos + saltLength);
        itCount = bytes[pos + saltLength];
        break;
      default:
        salt = Uint8List(0);
        break;
    }
    return GenericS2k(
      salt,
      type: type,
      hash: hash,
      itCount: itCount,
    );
  }

  @override
  Uint8List produceKey(final String passphrase, final int length) {
    switch (type) {
      case S2kType.simple:
        return _hashDigest(passphrase.toBytes(), length);
      case S2kType.salted:
        return _hashDigest(
          Uint8List.fromList([
            ...salt,
            ...passphrase.toBytes(),
          ]),
          length,
        );
      case S2kType.iterated:
        return _hashDigest(
          _iterate(Uint8List.fromList([
            ...salt,
            ...passphrase.toBytes(),
          ])),
          length,
        );
      default:
        throw UnsupportedError('S2k type not supported.');
    }
  }

  @override
  int get length => type.length;

  @override
  Uint8List get toBytes {
    final bytes = [type.value, hash.value];
    switch (type) {
      case S2kType.simple:
        return Uint8List.fromList(bytes);
      case S2kType.salted:
        return Uint8List.fromList([...bytes, ...salt]);
      case S2kType.iterated:
        return Uint8List.fromList([...bytes, ...salt, itCount]);
      case S2kType.gnu:
        return Uint8List.fromList([...bytes, ...utf8.encode('GNU'), 1]);
      case S2kType.argon2:
        throw UnsupportedError('Argon2 s2k type not supported.');
    }
  }

  Uint8List _iterate(final Uint8List data) {
    if (data.length > count) {
      return data;
    }
    final length = data.length;
    final result = Uint8List((count / length).ceil() * length);
    var pos = 0;
    while (pos < result.length) {
      result.setAll(pos, data);
      pos += length;
    }
    return result.sublist(0, count);
  }

  Uint8List _hashDigest(final Uint8List data, final int length) {
    var result = Helper.hashDigest(data, hash);
    while (result.length < length) {
      result = Uint8List.fromList([
        ...result,
        ...Helper.hashDigest(
          Uint8List.fromList([0, ...data]),
          hash,
        ),
      ]);
    }
    return result.sublist(0, length);
  }
}
