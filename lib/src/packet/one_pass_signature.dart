// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';
import 'key/key_id.dart';

/// OnePassSignature represents a one-pass signature packet.
/// See RFC 4880, section 5.4.
class OnePassSignaturePacket extends ContainedPacket {
  final int version;

  final SignatureType signatureType;

  final HashAlgorithm hashAlgorithm;

  final KeyAlgorithm keyAlgorithm;

  final KeyID issuerKeyID;

  final int nested;

  OnePassSignaturePacket(
    this.version,
    this.signatureType,
    this.hashAlgorithm,
    this.keyAlgorithm,
    this.issuerKeyID,
    this.nested, {
    super.tag = PacketTag.onePassSignature,
  });

  factory OnePassSignaturePacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos]);
    pos++;
    final hashAlgorithm = HashAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final issuerKeyID = bytes.sublist(pos, pos + 8);
    return OnePassSignaturePacket(
        version, signatureType, hashAlgorithm, keyAlgorithm, KeyID(issuerKeyID), bytes[pos + 8]);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      signatureType.value,
      hashAlgorithm.value,
      keyAlgorithm.value,
      ...issuerKeyID.id,
      nested,
    ]);
  }
}
