/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:collection';
import 'dart:typed_data';

import '../type/packet.dart';
import '../type/packet_list.dart';
import 'base_packet.dart';

/// This class represents a list of OpenPGP packets.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PacketList extends ListBase<PacketInterface> implements PacketListInterface {
  @override
  final List<PacketInterface> packets;

  PacketList(final Iterable<PacketInterface> packets)
      : packets = packets.toList(
          growable: false,
        );

  /// Decode packets from bytes
  factory PacketList.decode(Uint8List bytes) {
    final packets = <PacketInterface>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = PacketReader.read(bytes, offset);
      offset = reader.offset;
      final packet = switch (reader.type) {
        PacketType.publicKeyEncryptedSessionKey => PublicKeyEncryptedSessionKeyPacket.fromBytes(
            reader.data,
          ),
        PacketType.signature => SignaturePacket.fromBytes(reader.data),
        PacketType.symEncryptedSessionKey => SymEncryptedSessionKeyPacket.fromBytes(
            reader.data,
          ),
        PacketType.onePassSignature => OnePassSignaturePacket.fromBytes(
            reader.data,
          ),
        PacketType.secretKey => SecretKeyPacket.fromBytes(reader.data),
        PacketType.publicKey => PublicKeyPacket.fromBytes(reader.data),
        PacketType.secretSubkey => SecretSubkeyPacket.fromBytes(reader.data),
        PacketType.compressedData => CompressedDataPacket.fromBytes(
            reader.data,
          ),
        PacketType.symEncryptedData => SymEncryptedDataPacket.fromBytes(
            reader.data,
          ),
        PacketType.marker => MarkerPacket(),
        PacketType.literalData => LiteralDataPacket.fromBytes(reader.data),
        PacketType.trust => TrustPacket.fromBytes(reader.data),
        PacketType.userID => UserIDPacket.fromBytes(reader.data),
        PacketType.publicSubkey => PublicSubkeyPacket.fromBytes(reader.data),
        PacketType.userAttribute => UserAttributePacket.fromBytes(
            reader.data,
          ),
        PacketType.symEncryptedIntegrityProtectedData =>
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(reader.data),
        PacketType.aeadEncryptedData => AeadEncryptedDataPacket.fromBytes(
            reader.data,
          ),
        PacketType.padding => PaddingPacket(reader.data),
      };
      packets.add(packet);
    }
    return PacketList(packets);
  }

  @override
  encode() => Uint8List.fromList(
        packets
            .map(
              (packet) => packet.encode(),
            )
            .expand((byte) => byte)
            .toList(growable: false),
      );

  PacketListInterface filterByTypes([
    final List<PacketType> tags = const [],
  ]) {
    if (tags.isNotEmpty) {
      return PacketList(
        packets.where((packet) => tags.contains(packet.type)),
      );
    }
    return this;
  }

  List<int> indexOfTypes([
    final List<PacketType> tags = const [],
  ]) {
    final indexes = <int>[];
    for (var i = 0; i < packets.length; i++) {
      final packet = packets[i];
      if (tags.contains(packet.type)) {
        indexes.add(i);
      }
    }

    return indexes;
  }

  @override
  get length => packets.length;

  @override
  operator [](int index) => packets[index];

  @override
  operator []=(int index, PacketInterface packet) {
    packets[index] = packet;
  }

  @override
  set length(int newLength) {
    packets.length = newLength;
  }
}
