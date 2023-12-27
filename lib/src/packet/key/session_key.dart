// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/crypto/math/int_ext.dart';

import '../../crypto/math/byte_ext.dart';
import '../../enum/symmetric_algorithm.dart';
import '../../helpers.dart';

class SessionKey {
  /// Algorithm to encrypt the message with
  final SymmetricAlgorithm symmetric;

  /// Encryption key
  final Uint8List key;

  SessionKey(this.key, [this.symmetric = SymmetricAlgorithm.aes128]);

  factory SessionKey.produceKey([
    SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    return SessionKey(Helper.generateEncryptionKey(symmetric), symmetric);
  }

  /// Serializes session key to bytes
  Uint8List encode() => Uint8List.fromList([symmetric.value, ...key]);

  /// Compute checksum
  Uint8List computeChecksum() {
    var sum = 0;
    for (var i = 0; i < key.lengthInBytes; i++) {
      sum = (sum + key[i]) & 0xffff;
    }
    return sum.pack16();
  }

  @override
  bool operator ==(other) {
    if (other is! SessionKey) return false;
    return (other.symmetric == symmetric) && (other.key.equals(key));
  }

  @override
  int get hashCode {
    return symmetric.hashCode + key.hashCode;
  }
}
