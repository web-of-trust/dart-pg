// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/aead/base.dart';
import 'symmetric_algorithm.dart';

/// Aead Algorithms
/// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis#name-aead-encrypted-data-packet-
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum AeadAlgorithm {
  eax(1),
  ocb(2),
  gcm(100);

  final int value;

  const AeadAlgorithm(this.value);

  int get blockLength {
    switch (this) {
      case eax:
      case ocb:
      case gcm:
        return 16;
    }
  }

  int get ivLength {
    switch (this) {
      case eax:
        return 16;
      case ocb:
        return 15;
      case gcm:
        return 12;
    }
  }

  int get tagLength {
    switch (this) {
      case eax:
      case ocb:
      case gcm:
        return 16;
    }
  }

  Base cipherEngine(Uint8List key, SymmetricAlgorithm symmetric) {
    switch (this) {
      case eax:
        return Eax(key, symmetric);
      case ocb:
        return Ocb(key, symmetric);
      case gcm:
        return Gcm(key, symmetric);
    }
  }
}
