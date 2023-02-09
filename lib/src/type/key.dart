// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature.dart';
import 'public_key.dart';
import 'subkey.dart';
import 'user.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
abstract class Key {
  final KeyPacket keyPacket;

  final List<SignaturePacket> revocationSignatures;

  final List<SignaturePacket> directSignatures;

  final List<User> users;

  final List<Subkey> subkeys;

  Key(
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.directSignatures = const [],
    this.users = const [],
    this.subkeys = const [],
  });

  int get keyStrength => keyPacket.keyStrength;

  String get keyID => keyPacket.keyID.toString();

  bool get isPrivate;

  PublicKey get toPublic;

  /// Returns ASCII armored text of key
  String armor();

  PacketList toPacketList() {
    final packetList = PacketList([
      keyPacket,
      ...revocationSignatures,
      ...directSignatures,
    ]);
    for (final user in users) {
      packetList.addAll(user.toPacketList());
    }
    for (final subkey in subkeys) {
      packetList.addAll(subkey.toPacketList());
    }
    return packetList;
  }
}
