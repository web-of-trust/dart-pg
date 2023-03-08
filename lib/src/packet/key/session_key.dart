// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/crypto/math/int_ext.dart';

import '../../crypto/math/byte_ext.dart';
import '../../enum/symmetric_algorithm.dart';
import '../../helpers.dart';
import '../../openpgp.dart';

class SessionKey {
  /// Algorithm to encrypt the message with
  final SymmetricAlgorithm symmetric;

  /// Encryption key
  final Uint8List key;

  SessionKey(this.key, [this.symmetric = OpenPGP.preferredSymmetric]);

  Uint8List encode() => Uint8List.fromList([symmetric.value, ...key]);

  Uint8List computeChecksum() {
    var s = 0;
    for (var i = 0; i < key.lengthInBytes; i++) {
      s = (s + key[i]) & 0xffff;
    }
    return s.pack16();
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
