// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/secret_key.dart';
import '../packet/secret_subkey.dart';
import 'key.dart';
import 'public_key.dart';

/// Class that represents an OpenPGP Private key
class PrivateKey extends Key {
  PrivateKey(
    SecretKeyPacket? keyPacket, {
    List<SecretSubkeyPacket> subKeyPackets = const [],
    super.userIDPackets,
    super.userAttributes,
    super.signaturePackets,
  }) : super(keyPacket, subKeyPackets: subKeyPackets);

  @override
  bool get isPrivate => true;

  @override
  String get armor => Armor.encode(ArmorType.privateKey, toPacketList().packetEncode());

  @override
  PublicKey get toPublic {
    return PublicKey((keyPacket as SecretKeyPacket).publicKey);
  }
}
