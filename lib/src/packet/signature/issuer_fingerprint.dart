// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/helpers.dart';

import '../../crypto/math/byte_ext.dart';
import '../../enum/signature_subpacket_type.dart';
import '../key_packet.dart';
import '../signature_subpacket.dart';

/// packet giving the issuer key fingerprint.
class IssuerFingerprint extends SignatureSubpacket {
  IssuerFingerprint(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.issuerFingerprint, data);

  factory IssuerFingerprint.fromKey(final KeyPacket key) => IssuerFingerprint(
        Uint8List.fromList([key.version, ...key.fingerprint.hexToBytes()]),
      );

  int get keyVersion => data[0];

  String get fingerprint => data.sublist(1).toHexadecimal();
}
