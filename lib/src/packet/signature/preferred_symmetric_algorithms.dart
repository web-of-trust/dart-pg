// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../enum/symmetric_algorithm.dart';
import '../signature_subpacket.dart';

/// Symmetric algorithm numbers that indicate which algorithms the key
/// holder prefers to use.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.7
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PreferredSymmetricAlgorithms extends SignatureSubpacket {
  PreferredSymmetricAlgorithms(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.preferredSymmetricAlgorithms, data);

  List<SymmetricAlgorithm> get preferences => data
      .map((pref) =>
          SymmetricAlgorithm.values.firstWhere((alg) => alg.value == pref))
      .toList(growable: false);
}
