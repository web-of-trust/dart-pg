// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/hash_algorithm.dart';
import '../../enum/s2k_type.dart';
import '../../helpers.dart';

/// Implementation of the String-to-key specifier
///
/// String-to-key (S2K) specifiers are used to convert passphrase strings into symmetric-key encryption/decryption keys.
/// They are used in two places, currently: to encrypt the secret part of private keys in the private keyring,
/// and to convert passphrases to encryption keys for symmetrically encrypted messages.
class S2K {
  /// Default salt length
  static const saltLength = 8;

  /// Exponent bias, defined in RFC4880
  static const _expbias = 6;

  /// Default Iteration Count Byte
  static const _defaultItCount = 224;

  /// s2k identifier or 'gnu-dummy'
  final S2kType type;

  /// Hash function identifier, or 0 for gnu-dummy keys
  final HashAlgorithm hash;

  /// s2k iteration count
  final int itCount;

  /// Eight bytes of salt in a binary string.
  final Uint8List salt;

  /// s2k iteration count byte
  final int count;

  S2K(
    this.salt, {
    this.type = S2kType.iterated,
    this.hash = HashAlgorithm.sha1,
    this.itCount = _defaultItCount,
  }) : count = (16 + (itCount & 15)) << ((itCount >> 4) + _expbias);

  /// Parsing function for a string-to-key specifier
  factory S2K.fromByteData(final Uint8List bytes) {
    var pos = 0;
    var itCount = _defaultItCount;
    final type = S2kType.values.firstWhere(
      (type) => type.value == bytes[pos],
    );
    pos++;
    final hash = HashAlgorithm.values.firstWhere(
      (hash) => hash.value == bytes[pos],
    );
    pos++;

    final Uint8List salt;
    switch (type) {
      case S2kType.salted:
        salt = bytes.sublist(pos, pos + 8);
        break;
      case S2kType.iterated:
        salt = bytes.sublist(pos, pos + 8);
        itCount = bytes[pos + 8];
        break;
      default:
        salt = Uint8List(0);
        break;
    }
    return S2K(
      salt,
      type: type,
      hash: hash,
      itCount: itCount,
    );
  }

  int get length => type.length;

  /// Serializes s2k information
  Uint8List encode() {
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
    }
  }

  /// Produces a key using the specified passphrase and the defined hashAlgorithm
  Future<Uint8List> produceKey(
    final String passphrase,
    final int keyLen,
  ) async {
    switch (type) {
      case S2kType.simple:
        return _hash(passphrase.stringToBytes(), keyLen);
      case S2kType.salted:
        return _hash(
          Uint8List.fromList([
            ...salt,
            ...passphrase.stringToBytes(),
          ]),
          keyLen,
        );
      case S2kType.iterated:
        return _hash(
          _iterate(Uint8List.fromList([
            ...salt,
            ...passphrase.stringToBytes(),
          ])),
          keyLen,
        );
      default:
        throw UnsupportedError('s2k type not supported.');
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

  Uint8List _hash(final Uint8List data, final int size) {
    var result = Helper.hashDigest(data, hash);
    while (result.length < size) {
      result = Uint8List.fromList([
        ...result,
        ...Helper.hashDigest(
          Uint8List.fromList([0, ...data]),
          hash,
        ),
      ]);
    }
    return result.sublist(0, size);
  }
}
