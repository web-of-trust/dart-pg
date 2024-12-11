/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../enum/support_feature.dart';
import '../signature_subpacket.dart';

/// The Features subpacket denotes which advanced OpenPGP features a
/// user's implementation supports.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Features extends SignatureSubpacket {
  Features(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.features, data);

  factory Features.fromFeatures(
    final int features, {
    final bool critical = false,
  }) =>
      Features(Uint8List.fromList([features]), critical: critical);

  bool get seipdV1Supported =>
      (data[0] & SupportFeature.seipdV1.value) == SupportFeature.seipdV1.value;

  bool get aeadSupported =>
      (data[0] & SupportFeature.aead.value) == SupportFeature.aead.value;

  bool get publicKeyV5Supported =>
      (data[0] & SupportFeature.publicKeyV5.value) ==
      SupportFeature.publicKeyV5.value;

  bool get seidpV2Supported =>
      (data[0] & SupportFeature.seipdV2.value) == SupportFeature.seipdV2.value;
}
