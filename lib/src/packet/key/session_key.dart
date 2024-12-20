/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/aead_algorithm.dart';
import '../../type/session_key.dart';
import '../../common/helpers.dart';
import '../../enum/symmetric_algorithm.dart';

/// Session key class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class SessionKey implements SessionKeyInterface {
  @override
  final SymmetricAlgorithm symmetric;

  @override
  final Uint8List encryptionKey;

  @override
  final AeadAlgorithm? aead;

  SessionKey(
    this.encryptionKey, [
    this.symmetric = SymmetricAlgorithm.aes128,
    this.aead,
  ]);

  factory SessionKey.produceKey([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final AeadAlgorithm? aead,
  ]) =>
      SessionKey(
        Helper.generateEncryptionKey(symmetric),
        symmetric,
        aead,
      );

  factory SessionKey.fromBytes(final Uint8List data) {
    final sessionKeySymmetric = SymmetricAlgorithm.values.firstWhere(
      (algo) => algo.value == data[0],
    );
    final sessionKey = SessionKey(
      data.sublist(1, data.length - 2),
      sessionKeySymmetric,
    );
    sessionKey.checksum(data.sublist(data.length - 2));
    return sessionKey;
  }

  @override
  toBytes() => Uint8List.fromList(
        [symmetric.value, ...encryptionKey],
      );

  @override
  computeChecksum() {
    var sum = 0;
    for (var i = 0; i < encryptionKey.length; i++) {
      sum = (sum + encryptionKey[i]) & 0xffff;
    }
    return sum.pack16();
  }

  @override
  checksum(final Uint8List checksum) {
    final computed = computeChecksum();
    if (!((computed[0] == checksum[0]) && (computed[1] == checksum[1]))) {
      throw AssertionError(
        'Session key checksum mismatch!',
      );
    }
  }
}
