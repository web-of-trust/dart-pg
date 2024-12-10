/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import 'hash_algorithm.dart';
import 'kek_size.dart';
import 'symmetric_algorithm.dart';

/// Montgomery curves enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum MontgomeryCurve {
  x25519,
  x448;

  int get payloadSize => switch (this) {
        x25519 => 32,
        x448 => 56,
      };

  int get keyStrength => switch (this) {
        x25519 => 255,
        x448 => 448,
      };

  HashAlgorithm get hkdfHash => switch (this) {
        x25519 => HashAlgorithm.sha256,
        x448 => HashAlgorithm.sha512,
      };

  Uint8List get hkdfInfo => switch (this) {
        x25519 => 'OpenPGP X25519'.toBytes(),
        x448 => 'OpenPGP X448'.toBytes(),
      };

  int get kekSize => switch (this) {
        x25519 => KekSize.normal.size,
        x448 => KekSize.high.size,
      };

  SymmetricAlgorithm get symmetric => switch (this) {
        x25519 => SymmetricAlgorithm.aes128,
        x448 => SymmetricAlgorithm.aes256,
      };
}
