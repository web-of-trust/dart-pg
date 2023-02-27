// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../../helpers.dart';
import '../../openpgp.dart';

class SessionKey {
  /// Algorithm to encrypt the message with
  final SymmetricAlgorithm symmetric;

  /// Encryption key
  final Uint8List key;

  SessionKey(this.key, [this.symmetric = OpenPGP.preferredSymmetric]);

  Uint8List encode() => Uint8List.fromList([symmetric.value, ...key]);

  Uint8List checksum() => Helper.calculateChecksum(key);
}
