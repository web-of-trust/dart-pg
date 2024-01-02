// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/revocation_reason_tag.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket is used only in key revocation and certification
/// revocation signatures.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.23
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RevocationReason extends SignatureSubpacket {
  RevocationReason(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.revocationReason, data);

  factory RevocationReason.fromRevocation(
    final RevocationReasonTag reason,
    final String description, {
    final bool critical = false,
  }) =>
      RevocationReason(
        _revocationToBytes(reason, description),
        critical: critical,
      );

  RevocationReasonTag get reason => RevocationReasonTag.values.firstWhere(
        (reason) => reason.value == data[0],
      );

  String get description => utf8.decode(data.sublist(1));

  static Uint8List _revocationToBytes(
    final RevocationReasonTag reason,
    final String description,
  ) =>
      Uint8List.fromList([
        reason.value,
        ...utf8.encode(description),
      ]);
}
