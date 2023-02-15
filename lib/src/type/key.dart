// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
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

  DateTime get creationTime => keyPacket.creationTime;

  KeyAlgorithm get algorithm => keyPacket.algorithm;

  String get fingerprint => keyPacket.fingerprint;

  KeyID get keyID => keyPacket.keyID;

  KeyParams get publicParams => keyPacket.publicParams;

  int get keyStrength => keyPacket.keyStrength;

  bool get isPrivate;

  PublicKey get toPublic;

  /// Returns ASCII armored text of key
  String armor();

  PacketList toPacketList() => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...directSignatures,
        ...users.map((user) => user.toPacketList()).expand((packet) => packet),
        ...subkeys.map((subkey) => subkey.toPacketList()).expand((packet) => packet),
      ]);
}
