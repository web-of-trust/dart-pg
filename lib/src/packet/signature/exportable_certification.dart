/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket denotes whether a certification signature is
/// "exportable", to be used by other users than the signature's issuer.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.11
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ExportableCertification extends SignatureSubpacket {
  ExportableCertification(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.exportableCertification, data);

  factory ExportableCertification.fromExportable(
    final bool exportable, {
    final bool critical = false,
  }) =>
      ExportableCertification(
        Uint8List.fromList([exportable ? 1 : 0]),
        critical: critical,
      );

  bool get isExportable => data[0] != 0;
}
