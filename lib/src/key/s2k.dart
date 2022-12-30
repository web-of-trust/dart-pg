// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../enums.dart';

/// Implementation of the String-to-key specifier
///
/// String-to-key (S2K) specifiers are used to convert passphrase strings into symmetric-key encryption/decryption keys.
/// They are used in two places, currently: to encrypt the secret part of private keys in the private keyring,
/// and to convert passphrases to encryption keys for symmetrically encrypted messages.
class S2K {
  /// Exponent bias, defined in RFC4880
  static const expbias = 6;

  /// s2k identifier or 'gnu-dummy'
  final S2kType type;

  /// Hash function identifier, or 0 for gnu-dummy keys
  final HashAlgorithm hash;

  /// s2k iteration count byte
  final int itCount;

  /// Eight bytes of salt in a binary string.
  final Uint8List salt;

  final Digest _digest;

  S2K(
    this.salt, {
    this.type = S2kType.iterated,
    this.hash = HashAlgorithm.sha256,
    this.itCount = 224,
  }) : _digest = Digest(hash.digestName);

  factory S2K.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var itCount = 224;
    final type = S2kType.values.firstWhere((type) => type.value == bytes[pos++]);
    final hash = HashAlgorithm.values.firstWhere((hash) => hash.value == bytes[pos++]);
    final List<int> salt = [];
    switch (type) {
      case S2kType.simple:
        break;
      case S2kType.salted:
        salt.addAll(bytes.sublist(pos, pos + 8));
        break;
      case S2kType.iterated:
        salt.addAll(bytes.sublist(pos, pos + 8));
        itCount = bytes[pos + 8];
        break;
      case S2kType.gnu:
        break;
    }
    return S2K(Uint8List.fromList(salt), type: type, hash: hash, itCount: itCount);
  }

  int get count => (16 + (itCount & 15)) << ((itCount >> 4) + expbias);

  Uint8List encode() {
    final List<int> bytes = [type.value, hash.value];
    switch (type) {
      case S2kType.simple:
        break;
      case S2kType.salted:
        bytes.addAll(salt);
        break;
      case S2kType.iterated:
        bytes.addAll([...salt, itCount]);
        break;
      case S2kType.gnu:
        bytes.addAll([...utf8.encode('GNU'), 1]);
        break;
    }
    return Uint8List.fromList(bytes);
  }

  Uint8List produceKey(String passphrase, SymmetricAlgorithm algorithm) {
    final List<int> bytes = [];

    var rLen = 0;
    var prefixLen = 0;
    while (rLen < algorithm.keySize) {
      final Uint8List toHash;
      switch (type) {
        case S2kType.simple:
          toHash = Uint8List.fromList([prefixLen, ...utf8.encode(passphrase)]);
          break;
        case S2kType.salted:
          toHash = Uint8List.fromList([prefixLen, ...salt, ...utf8.encode(passphrase)]);
          break;
        case S2kType.iterated:
          final data = [...salt, ...utf8.encode(passphrase)];
          var dataLen = data.length;
          final count = max(this.count, dataLen);
          toHash = Uint8List(prefixLen + count);
          toHash.setAll(prefixLen, data);
          for (var pos = prefixLen + dataLen; pos < count; pos += dataLen, dataLen *= 2) {
            toHash.setAll(pos, toHash.sublist(prefixLen, pos));
          }
          break;
        default:
          toHash = Uint8List.fromList([]);
      }
      final result = _digest.process(toHash);
      bytes.addAll(result);
      rLen += result.length;
      prefixLen++;
    }

    return Uint8List.fromList(bytes);
  }
}
