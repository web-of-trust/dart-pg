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

  bool get supprtVersion1SEIPD => (data[0] & SupportFeature.version1SEIPD.value) == SupportFeature.version1SEIPD.value;

  bool get supportAeadEncrypted => (data[0] & SupportFeature.aeadEncrypted.value) == SupportFeature.aeadEncrypted.value;

  bool get supportVersion5PublicKey =>
      (data[0] & SupportFeature.version5PublicKey.value) == SupportFeature.version5PublicKey.value;

  bool get supportVersion2SEIPD => (data[0] & SupportFeature.version2SEIPD.value) == SupportFeature.version2SEIPD.value;
}
