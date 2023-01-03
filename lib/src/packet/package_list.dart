// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'compressed_data.dart';
import 'contained_packet.dart';
import 'literal_data.dart';
import 'marker_packet.dart';
import 'one_pass_signature.dart';
import 'packet_data.dart';
import 'public_key.dart';
import 'public_key_encrypted_session_key.dart';
import 'public_subkey.dart';
import 'secret_key.dart';
import 'secret_subkey.dart';
import 'signature.dart';
import 'sym_encrypted_integrity_protected_data.dart';
import 'sym_encrypted_session_key.dart';
import 'symmetrically_encrypted_data.dart';
import 'trust_packet.dart';
import 'user_attribute.dart';
import 'user_id.dart';

/// This class represents a list of openpgp packets.
/// Take care when iterating over it - the packets themselves
/// are stored as numerical indices.
class PacketList {
  final List<ContainedPacket> packets = [];

  void packetDecode(Uint8List bytes) {
    var offset = 0;
    while (offset < bytes.length) {
      final packetData = PacketData.readPacketData(bytes, offset);
      offset = packetData.offset;

      switch (packetData.tag) {
        case PacketTag.publicKeyEncryptedSessionKey:
          packets.add(PublicKeyEncryptedSessionKey.fromPacketData(packetData.data));
          break;
        case PacketTag.signature:
          packets.add(Signature.fromPacketData(packetData.data));
          break;
        case PacketTag.symEncryptedSessionKey:
          packets.add(SymEncryptedSessionKey.fromPacketData(packetData.data));
          break;
        case PacketTag.onePassSignature:
          packets.add(OnePassSignature.fromPacketData(packetData.data));
          break;
        case PacketTag.secretKey:
          packets.add(SecretKey.fromPacketData(packetData.data));
          break;
        case PacketTag.publicKey:
          packets.add(PublicKey.fromPacketData(packetData.data));
          break;
        case PacketTag.secretSubkey:
          packets.add(SecretSubkey.fromPacketData(packetData.data));
          break;
        case PacketTag.compressedData:
          packets.add(CompressedData.fromPacketData(packetData.data));
          break;
        case PacketTag.symmetricallyEncryptedData:
          packets.add(SymmetricallyEncryptedData.fromPacketData(packetData.data));
          break;
        case PacketTag.marker:
          packets.add(MarkerPacket());
          break;
        case PacketTag.literalData:
          packets.add(LiteralData.fromPacketData(packetData.data));
          break;
        case PacketTag.trust:
          packets.add(TrustPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.userID:
          packets.add(UserID.fromPacketData(packetData.data));
          break;
        case PacketTag.publicSubkey:
          packets.add(PublicSubkey.fromPacketData(packetData.data));
          break;
        case PacketTag.userAttribute:
          packets.add(UserAttribute.fromPacketData(packetData.data));
          break;
        case PacketTag.symEncryptedIntegrityProtectedData:
          packets.add(SymEncryptedIntegrityProtectedData.fromPacketData(packetData.data));
          break;
        default:
      }
    }
  }

  Uint8List packetEncode() {
    List<int> packetBytes = [];
    for (var packet in packets) {
      packetBytes.addAll(packet.packetEncode());
    }
    return Uint8List.fromList(packetBytes);
  }
}
