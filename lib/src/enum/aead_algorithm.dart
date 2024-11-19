/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../cryptor/aead/eax.dart';
import '../cryptor/aead/gcm.dart';
import '../cryptor/aead/ocb.dart';
import '../type/aead.dart';
import 'symmetric_algorithm.dart';

/// Aead Algorithms
/// See https://www.rfc-editor.org/rfc/rfc9580#section-9.6
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum AeadAlgorithm {
  eax(1),
  ocb(2),
  gcm(3);

  final int value;

  const AeadAlgorithm(this.value);

  int get blockLength => 16;

  int get ivLength => switch (this) {
        eax => 16,
        ocb => 15,
        gcm => 12,
      };

  int get tagLength => 16;

  AeadInterface cipherEngine(
    Uint8List key, [
    SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) =>
      switch (this) {
        eax => Eax(key, symmetric),
        ocb => Ocb(key, symmetric),
        gcm => Gcm(key, symmetric),
      };
}
