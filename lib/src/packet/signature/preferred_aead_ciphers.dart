/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/aead_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../../enum/symmetric_algorithm.dart';
import '../signature_subpacket.dart';

/// The PreferredAeadCiphers sub-packet class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PreferredAeadCiphers extends SignatureSubpacket {
  PreferredAeadCiphers(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(
          SignatureSubpacketType.preferredAeadCiphers,
          data,
        );

  bool isPreferred(
    final SymmetricAlgorithm symmetric,
    final AeadAlgorithm aead,
  ) {
    if (data.isEmpty) {
      return true;
    } else {
      const chunkSize = 2;
      var data = this.data;
      while (data.isNotEmpty) {
        final size = chunkSize < data.length ? chunkSize : data.length;
        final ciphers = data.sublist(0, size);
        if (ciphers.elementAtOrNull(1) != null) {
          final preferredSymmetric = SymmetricAlgorithm.values.firstWhere(
            (alg) => alg.value == ciphers.elementAt(0),
          );
          final preferredAead = AeadAlgorithm.values.firstWhere(
            (alg) => alg.value == ciphers.elementAt(1),
          );
          if (symmetric == preferredSymmetric && aead == preferredAead) {
            return true;
          }
        }
        data = data.sublist(size);
      }
      return false;
    }
  }
}
