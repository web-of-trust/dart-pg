/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/hash_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Message digest algorithm numbers that indicate which algorithms the
/// key holder prefers to receive.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PreferredHashAlgorithms extends SignatureSubpacket {
  PreferredHashAlgorithms(
    final Uint8List data, {
    super.critical,
  }) : super(SignatureSubpacketType.preferredHashAlgorithms, data);

  List<HashAlgorithm> get preferences => data
      .map(
        (pref) => HashAlgorithm.values.firstWhere(
          (alg) => alg.value == pref,
        ),
      )
      .toList();
}
