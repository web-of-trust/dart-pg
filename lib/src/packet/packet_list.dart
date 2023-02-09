// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:collection';
import 'dart:typed_data';

import '../enums.dart';
import 'aead_encrypted_data.dart';
import 'compressed_data.dart';
import 'contained_packet.dart';
import 'literal_data.dart';
import 'marker_packet.dart';
import 'modification_detection_code.dart';
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
class PacketList extends ListBase<ContainedPacket> {
  final List<ContainedPacket> packets;

  PacketList(this.packets);

  factory PacketList.packetDecode(Uint8List bytes) {
    final List<ContainedPacket> packets = [];
    var offset = 0;
    while (offset < bytes.length) {
      final packetData = PacketData.readPacketData(bytes, offset);
      offset = packetData.end;

      switch (packetData.tag) {
        case PacketTag.publicKeyEncryptedSessionKey:
          packets.add(PublicKeyEncryptedSessionKeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.signature:
          packets.add(SignaturePacket.fromPacketData(packetData.data));
          break;
        case PacketTag.symEncryptedSessionKey:
          packets.add(SymEncryptedSessionKeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.onePassSignature:
          packets.add(OnePassSignaturePacket.fromPacketData(packetData.data));
          break;
        case PacketTag.secretKey:
          packets.add(SecretKeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.publicKey:
          packets.add(PublicKeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.secretSubkey:
          packets.add(SecretSubkeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.compressedData:
          packets.add(CompressedDataPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.symmetricallyEncryptedData:
          packets.add(SymmetricallyEncryptedDataPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.marker:
          packets.add(MarkerPacket());
          break;
        case PacketTag.literalData:
          packets.add(LiteralDataPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.trust:
          packets.add(TrustPacketPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.userID:
          packets.add(UserIDPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.publicSubkey:
          packets.add(PublicSubkeyPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.userAttribute:
          packets.add(UserAttributePacket.fromPacketData(packetData.data));
          break;
        case PacketTag.symEncryptedIntegrityProtectedData:
          packets.add(SymEncryptedIntegrityProtectedDataPacket.fromPacketData(packetData.data));
          break;
        case PacketTag.modificationDetectionCode:
          packets.add(ModificationDetectionCodePacket.fromPacketData(packetData.data));
          break;
        case PacketTag.aeadEncryptedData:
          packets.add(AEADEncryptedDataPacket.fromPacketData(packetData.data));
          break;
      }
    }
    return PacketList(packets);
  }

  Uint8List packetEncode() {
    List<int> packetBytes = [];
    for (final packet in packets) {
      packetBytes.addAll(packet.packetEncode());
    }
    return Uint8List.fromList(packetBytes);
  }

  @override
  int get length => packets.length;

  @override
  ContainedPacket operator [](int index) => packets[index];

  @override
  void operator []=(int index, ContainedPacket packet) {
    packets[index] = packet;
  }

  @override
  set length(int newLength) {
    packets.length = newLength;
  }
}
