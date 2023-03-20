// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/signature_type.dart';
import 'contained_packet.dart';
import 'key/key_id.dart';

/// OnePassSignature represents a One-Pass Signature packet.
/// See RFC 4880, section 5.4.
///
/// The One-Pass Signature packet precedes the signed data and contains enough information
/// to allow the receiver to begin calculating any hashes needed to verify the signature.
/// It allows the Signature packet to be placed at the end of the message,
/// so that the signer can compute the entire signed message in one pass.
class OnePassSignaturePacket extends ContainedPacket {
  static const version = 3;

  final SignatureType signatureType;

  final HashAlgorithm hashAlgorithm;

  final KeyAlgorithm keyAlgorithm;

  final KeyID issuerKeyID;

  final int nested;

  OnePassSignaturePacket(
    this.signatureType,
    this.hashAlgorithm,
    this.keyAlgorithm,
    this.issuerKeyID,
    this.nested,
  ) : super(PacketTag.onePassSignature);

  factory OnePassSignaturePacket.fromByteData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    if (version != 3) {
      throw UnsupportedError(
        'Version $version of the one-pass signature packet is unsupported.',
      );
    }

    final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos]);
    pos++;
    final hashAlgorithm = HashAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final issuerKeyID = bytes.sublist(pos, pos + 8);
    return OnePassSignaturePacket(
      signatureType,
      hashAlgorithm,
      keyAlgorithm,
      KeyID(issuerKeyID),
      bytes[pos + 8],
    );
  }

  @override
  Uint8List toByteData() {
    return Uint8List.fromList([
      version,
      signatureType.value,
      hashAlgorithm.value,
      keyAlgorithm.value,
      ...issuerKeyID.bytes,
      nested,
    ]);
  }
}
