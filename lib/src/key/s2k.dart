// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/api.dart' as pc;

import '../enums.dart';
import '../helpers.dart';

/// Implementation of the String-to-key specifier
///
/// String-to-key (S2K) specifiers are used to convert passphrase strings into symmetric-key encryption/decryption keys.
/// They are used in two places, currently: to encrypt the secret part of private keys in the private keyring,
/// and to convert passphrases to encryption keys for symmetrically encrypted messages.
class S2K {
  /// Exponent bias, defined in RFC4880
  static const _expbias = 6;

  /// Default Iteration Count Byte
  static const _defaultItCount = 224;

  /// s2k identifier or 'gnu-dummy'
  final S2kType type;

  /// Hash function identifier, or 0 for gnu-dummy keys
  final HashAlgorithm hash;

  /// s2k iteration count byte
  final int itCount;

  /// Eight bytes of salt in a binary string.
  final Uint8List salt;

  S2K(
    this.salt, {
    this.type = S2kType.iterated,
    this.hash = HashAlgorithm.sha1,
    this.itCount = _defaultItCount,
  });

  factory S2K.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var itCount = _defaultItCount;
    final type = S2kType.values.firstWhere((type) => type.value == bytes[pos]);
    pos++;
    final hash = HashAlgorithm.values.firstWhere((hash) => hash.value == bytes[pos]);
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
    return S2K(salt, type: type, hash: hash, itCount: itCount);
  }

  int get count => (16 + (itCount & 15)) << ((itCount >> 4) + _expbias);

  Uint8List encode() {
    final bytes = [type.value, hash.value];
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
    final List<int> keyBytes = [];
    final pBytes = passphrase.stringToBytes();

    var rLen = 0;
    var prefixLen = 0;
    final keyLen = (algorithm.keySize + 7) >> 3;
    while (rLen < keyLen) {
      final Uint8List toHash;
      switch (type) {
        case S2kType.simple:
          toHash = Uint8List.fromList([...List.filled(prefixLen, 0), ...utf8.encode(passphrase)]);
          break;
        case S2kType.salted:
          toHash = Uint8List.fromList([...List.filled(prefixLen, 0), ...salt, ...utf8.encode(passphrase)]);
          break;
        case S2kType.iterated:
          final data = [...List.filled(prefixLen, 0), ...salt, ...pBytes];
          toHash = Uint8List(this.count);
          toHash.setAll(0, data);
          var count = this.count - data.length;
          var pos = data.length;
          while (count > 0) {
            if (count < salt.length) {
              toHash.setAll(pos, salt.sublist(0, count));
              break;
            } else {
              toHash.setAll(pos, salt);
              count -= salt.length;
              pos += salt.length;
            }

            if (count < pBytes.length) {
              toHash.setAll(pos, pBytes.sublist(0, count));
              count = 0;
            } else {
              toHash.setAll(pos, pBytes);
              count -= pBytes.length;
              pos += pBytes.length;
            }
          }
          break;
        default:
          throw UnsupportedError('s2k type not supported.');
      }
      final result = hashDigest(toHash);
      keyBytes.addAll(result);
      rLen += result.length;
      prefixLen++;
    }

    return Uint8List.fromList(keyBytes.sublist(0, keyLen));
  }

  Uint8List hashDigest(Uint8List input) {
    switch (hash) {
      case HashAlgorithm.sha1:
        return Uint8List.fromList(sha1.convert(input).bytes);
      case HashAlgorithm.ripemd160:
        final digest = pc.Digest('RIPEMD-160');
        return digest.process(input);
      case HashAlgorithm.sha256:
        return Uint8List.fromList(sha256.convert(input).bytes);
      case HashAlgorithm.sha384:
        return Uint8List.fromList(sha384.convert(input).bytes);
      case HashAlgorithm.sha512:
        return Uint8List.fromList(sha512.convert(input).bytes);
      case HashAlgorithm.sha224:
        return Uint8List.fromList(sha224.convert(input).bytes);
      default:
        throw UnsupportedError('Digest type not supported.');
    }
  }
}
