// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/compression_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PreferredCompressionAlgorithms extends SignatureSubpacket {
  PreferredCompressionAlgorithms(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(
          SignatureSubpacketType.preferredCompressionAlgorithms,
          data,
        );

  List<CompressionAlgorithm> get preferences => data
      .map((pref) =>
          CompressionAlgorithm.values.firstWhere((alg) => alg.value == pref))
      .toList();
}
