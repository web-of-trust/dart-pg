// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/symmetric_algorithm.dart';
import 'session_key.dart';

export 'ecdh_session_key_params.dart';
export 'elgamal_session_key_params.dart';
export 'rsa_session_key_params.dart';

/// Session key params
abstract class SessionKeyParams {
  Uint8List encode();

  SessionKey decodeSessionKey(final Uint8List data) {
    final sessionKeySymmetric =
        SymmetricAlgorithm.values.firstWhere((algo) => algo.value == data[0]);
    final sessionKey =
        SessionKey(data.sublist(1, data.length - 2), sessionKeySymmetric);
    final checksum = data.sublist(data.length - 2);
    final computedChecksum = sessionKey.computeChecksum();
    final isValidChecksum = (computedChecksum[0] == checksum[0]) &&
        (computedChecksum[1] == checksum[1]);
    if (!isValidChecksum) {
      throw StateError('Session key decryption error');
    }
    return sessionKey;
  }
}
