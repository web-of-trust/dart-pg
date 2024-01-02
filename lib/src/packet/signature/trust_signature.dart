// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Signer asserts that the key is not only valid but also trustworthy at
/// the specified level.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.13
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class TrustSignature extends SignatureSubpacket {
  TrustSignature(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.trustSignature, data);

  factory TrustSignature.fromTrust(
    final int trustLevel,
    final int trustAmount, {
    final bool critical = false,
  }) =>
      TrustSignature(
        Uint8List.fromList([trustLevel, trustAmount]),
        critical: critical,
      );

  int get trustLevel => data[0];

  int get trustAmount => data[1];
}
