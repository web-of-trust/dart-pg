// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../enum/support_feature.dart';
import '../signature_subpacket.dart';

/// The Features subpacket denotes which advanced OpenPGP features a
/// user's implementation supports.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.24
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Features extends SignatureSubpacket {
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

  bool get supprtModificationDetection =>
      (data[0] & SupportFeature.modificationDetection.value) ==
      SupportFeature.modificationDetection.value;

  bool get supportAeadEncryptedData =>
      (data[0] & SupportFeature.aeadEncryptedData.value) ==
      SupportFeature.aeadEncryptedData.value;

  bool get supportVersion5PublicKey =>
      (data[0] & SupportFeature.version5PublicKey.value) ==
      SupportFeature.version5PublicKey.value;
}
