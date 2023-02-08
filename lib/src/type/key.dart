// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature.dart';
import '../packet/subkey_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'public_key.dart';
import 'subkey.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
abstract class Key {
  final KeyPacket? keyPacket;

  final List<SubkeyPacket> subKeyPackets;

  final List<UserIDPacket> userIDPackets;

  final List<UserAttributePacket> userAttributes;

  final List<SignaturePacket> signaturePackets;

  Key(
    this.keyPacket, {
    this.subKeyPackets = const [],
    this.userIDPackets = const [],
    this.userAttributes = const [],
    this.signaturePackets = const [],
  });

  bool get isPrivate;

  String get armor;

  PublicKey get toPublic;

  List<Subkey> get subKeys => subKeyPackets.map((packet) {
        final bindingSignatures = signaturePackets
            .where((packet) => packet.signatureType == SignatureType.subkeyBinding)
            .toList(growable: false);
        final revocationSignatures = signaturePackets
            .where((packet) => packet.signatureType == SignatureType.subkeyRevocation)
            .toList(growable: false);
        return Subkey(
          packet,
          this,
          bindingSignatures: bindingSignatures,
          revocationSignatures: revocationSignatures,
        );
      }).toList(growable: false);

  List<SignaturePacket> get directSignatures =>
      signaturePackets.where((packet) => packet.signatureType == SignatureType.key).toList(growable: false);

  List<SignaturePacket> get revocationSignatures =>
      signaturePackets.where((packet) => packet.signatureType == SignatureType.keyRevocation).toList(growable: false);

  PacketList toPacketList() {
    return PacketList([
      keyPacket!,
      ...subKeyPackets,
      ...userIDPackets,
      ...userAttributes,
      ...signaturePackets,
    ]);
  }
}
