// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../byte_utils.dart';
import '../enums.dart';
import 'contained_packet.dart';

class OnePassSignature extends ContainedPacket {
  static const tag = PacketTag.onePassSignature;

  final int version;

  final SignatureType signatureType;

  final HashAlgorithm hashAlgorithm;

  final KeyAlgorithm keyAlgorithm;

  final int issuerKeyID;

  final int nested;

  OnePassSignature(
    this.version,
    this.signatureType,
    this.hashAlgorithm,
    this.keyAlgorithm,
    this.issuerKeyID,
    this.nested,
  );

  factory OnePassSignature.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos++]);
    final hashAlgorithm = HashAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    final issuerKeyID = ByteUtils.bytesToInt64(bytes.sublist(pos, pos + 8));
    return OnePassSignature(version, signatureType, hashAlgorithm, keyAlgorithm, issuerKeyID, bytes[pos + 8]);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      signatureType.value,
      hashAlgorithm.value,
      keyAlgorithm.value,
      ...ByteUtils.int64Bytes(issuerKeyID),
      nested,
    ]);
  }
}
