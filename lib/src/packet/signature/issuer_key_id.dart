// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/byte_ext.dart';
import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// packet giving the issuer key ID.
class IssuerKeyID extends SignatureSubpacket {
  IssuerKeyID(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.issuerKeyID, data);

  factory IssuerKeyID.fromString(final String id, {final bool critical = false}) =>
      IssuerKeyID(id.hexToBytes(), critical: critical);

  factory IssuerKeyID.wildcard() => IssuerKeyID(Uint8List.fromList(List.filled(8, 0, growable: false)));

  String get id => data.toHexadecimal();
}
