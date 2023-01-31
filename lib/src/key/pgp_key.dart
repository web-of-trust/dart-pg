// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'public_key.dart';
import 'subkey.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
abstract class PgpKey {
  final KeyPacket keyPacket;

  final List<Subkey> subKeys;

  final List<SignaturePacket> directSignatures;

  final List<SignaturePacket> revocationSignatures;

  final List<UserIDPacket> users;

  final List<UserAttributePacket> userAttributes;

  PgpKey(
    this.keyPacket,
    this.subKeys, {
    this.directSignatures = const [],
    this.revocationSignatures = const [],
    this.users = const [],
    this.userAttributes = const [],
  });

  bool get isPrivate;

  String get armor;

  PublicKey get toPublic;

  PacketList toPacketList() {
    final packets = [
      keyPacket,
      ...users,
      ...userAttributes,
      ...directSignatures,
      ...revocationSignatures,
    ];
    for (var subKey in subKeys) {
      packets.addAll(subKey.toPacketList());
    }
    return PacketList(packets);
  }
}
