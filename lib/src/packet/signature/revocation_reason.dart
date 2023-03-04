// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/revocation_reason_tag.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Represents revocation reason OpenPGP signature sub packet.
class RevocationReason extends SignatureSubpacket {
  RevocationReason(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.revocationReason, data);

  factory RevocationReason.fromRevocation(
    final RevocationReasonTag reason,
    final String description, {
    final bool critical = false,
  }) =>
      RevocationReason(_revocationToBytes(reason, description), critical: critical);

  RevocationReasonTag get reason => RevocationReasonTag.values.firstWhere((reason) => reason.value == data[0]);

  String get description => utf8.decode(data.sublist(1));

  static Uint8List _revocationToBytes(final RevocationReasonTag reason, final String description) =>
      Uint8List.fromList([reason.value, ...utf8.encode(description)]);
}
