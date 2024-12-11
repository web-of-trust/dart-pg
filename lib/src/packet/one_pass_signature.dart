/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/signature_type.dart';
import '../type/signature_packet.dart';
import 'base_packet.dart';

/// Implementation an OpenPGP One-Pass (OPS) Signature Packet - Type 4.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class OnePassSignaturePacket extends BasePacket {
  final int version;

  final SignatureType signatureType;

  final HashAlgorithm hashAlgorithm;

  final KeyAlgorithm keyAlgorithm;

  final Uint8List salt;

  final Uint8List issuerFingerprint;

  final Uint8List issuerKeyID;

  final int nested;

  OnePassSignaturePacket(
    this.version,
    this.signatureType,
    this.hashAlgorithm,
    this.keyAlgorithm,
    this.salt,
    this.issuerFingerprint,
    this.issuerKeyID, [
    this.nested = 0,
  ]) : super(PacketType.onePassSignature) {
    if (version != 3 && version != 6) {
      throw UnsupportedError(
        'Version $version of the OPS packet is unsupported.',
      );
    }
  }

  factory OnePassSignaturePacket.fromBytes(
    final Uint8List bytes,
  ) {
    var pos = 0;

    /// A one-octet version number (4 or 6).
    final version = bytes[pos++];

    /// One-octet signature type.
    final signatureType = SignatureType.values.firstWhere(
      (type) => type.value == bytes[pos],
    );
    pos++;

    /// One-octet hash algorithm.
    final hashAlgorithm = HashAlgorithm.values.firstWhere(
      (alg) => alg.value == bytes[pos],
    );
    pos++;

    /// One-octet public-key algorithm.
    final keyAlgorithm = KeyAlgorithm.values.firstWhere(
      (alg) => alg.value == bytes[pos],
    );
    pos++;

    final Uint8List salt;
    final Uint8List issuerFingerprint;
    final Uint8List issuerKeyID;
    if (version == 6) {
      final saltLength = bytes[pos++];
      salt = bytes.sublist(pos, pos + saltLength);
      pos += saltLength;

      issuerFingerprint = bytes.sublist(pos, pos + 32);
      pos += 32;

      issuerKeyID = issuerFingerprint.sublist(0, 8);
    } else {
      salt = issuerFingerprint = Uint8List(0);
      issuerKeyID = bytes.sublist(pos, pos + 8);
      pos += 8;
    }

    return OnePassSignaturePacket(
      version,
      signatureType,
      hashAlgorithm,
      keyAlgorithm,
      salt,
      issuerFingerprint,
      issuerKeyID,
      bytes[pos],
    );
  }

  factory OnePassSignaturePacket.fromSignature(
    final SignaturePacketInterface signature, [
    int nested = 0,
  ]) {
    return OnePassSignaturePacket(
      signature.version == 6 ? 6 : 3,
      signature.signatureType,
      signature.hashAlgorithm,
      signature.keyAlgorithm,
      signature.salt,
      signature.issuerFingerprint,
      signature.issuerKeyID,
      nested,
    );
  }

  @override
  get data => Uint8List.fromList([
        version,
        signatureType.value,
        hashAlgorithm.value,
        keyAlgorithm.value,
        ...version == 6 ? [salt.length] : [],
        ...version == 6 ? salt : [],
        ...version == 6 ? issuerFingerprint : [],
        ...version == 3 ? issuerKeyID : [],
        nested,
      ]);
}
