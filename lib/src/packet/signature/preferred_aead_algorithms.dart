// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/aead_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

class PreferredAeadAlgorithms extends SignatureSubpacket {
  PreferredAeadAlgorithms(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(
          SignatureSubpacketType.preferredCompressionAlgorithms,
          data,
        );

  List<AeadAlgorithm> get preferences =>
      data.map((pref) => AeadAlgorithm.values.firstWhere((alg) => alg.value == pref)).toList();
}
