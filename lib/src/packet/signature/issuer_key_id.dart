/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The OpenPGP Key ID of the key issuing the signature.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.5
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class IssuerKeyID extends SignatureSubpacket {
  IssuerKeyID(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.issuerKeyID, data);

  factory IssuerKeyID.fromString(
    final String id, {
    final bool critical = false,
  }) =>
      IssuerKeyID(id.hexToBytes(), critical: critical);

  Uint8List get keyID => data;
}
