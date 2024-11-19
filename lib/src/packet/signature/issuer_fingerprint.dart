/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/type/key_packet.dart';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The OpenPGP Key fingerprint of the key issuing the signature.
/// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis#section-5.2.3.28
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class IssuerFingerprint extends SignatureSubpacket {
  IssuerFingerprint(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(
          SignatureSubpacketType.issuerFingerprint,
          data,
        );

  factory IssuerFingerprint.fromKey(
    final KeyPacketInterface key,
  ) =>
      IssuerFingerprint(
        Uint8List.fromList([
          key.keyVersion,
          ...key.fingerprint,
        ]),
      );

  int get keyVersion => data[0];

  Uint8List get fingerprint => data.sublist(1);
}
