// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../signature_subpacket.dart';

/// packet giving trust.
class TrustSignature extends SignatureSubpacket {
  TrustSignature(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.trustSignature, data);

  factory TrustSignature.fromTrust(
    final int trustLevel,
    final int trustAmount, {
    final bool critical = false,
  }) =>
      TrustSignature(Uint8List.fromList([trustLevel, trustAmount]), critical: critical);

  int get trustLevel => data[0];

  int get trustAmount => data[1];
}
