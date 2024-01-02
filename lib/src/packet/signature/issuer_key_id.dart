// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/byte_ext.dart';
import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// Packet giving the issuer key ID.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class IssuerKeyID extends SignatureSubpacket {
  IssuerKeyID(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.issuerKeyID, data);

  factory IssuerKeyID.fromString(
    final String id, {
    final bool critical = false,
  }) =>
      IssuerKeyID(id.hexToBytes(), critical: critical);

  factory IssuerKeyID.wildcard() => IssuerKeyID(
        Uint8List.fromList(List.filled(8, 0, growable: false)),
      );

  String get id => data.toHexadecimal();
}
