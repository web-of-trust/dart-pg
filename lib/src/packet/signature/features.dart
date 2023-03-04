// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../enum/support_feature.dart';
import '../signature_subpacket.dart';

class Features extends SignatureSubpacket {
  Features(final Uint8List data, {super.critical, super.isLongLength}) : super(SignatureSubpacketType.features, data);

  factory Features.fromFeatures(final int features, {final bool critical = false}) =>
      Features(Uint8List.fromList([features]), critical: critical);

  bool get supprtModificationDetection =>
      (data[0] & SupportFeature.modificationDetection.value) == SupportFeature.modificationDetection.value;

  bool get supportAeadEncryptedData =>
      (data[0] & SupportFeature.aeadEncryptedData.value) == SupportFeature.aeadEncryptedData.value;

  bool get supportVersion5PublicKey =>
      (data[0] & SupportFeature.version5PublicKey.value) == SupportFeature.version5PublicKey.value;
}
