// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/subkey_packet.dart';

/// Class that represents a subkey packet and the relevant signatures.
class Subkey {
  /// subkey packet to hold in the Subkey
  final SubkeyPacket keyPacket;

  final List<SignaturePacket> revocationSignatures = [];

  final List<SignaturePacket> bindingSignatures = [];

  Subkey(this.keyPacket);

  DateTime get creationTime => keyPacket.creationTime;

  KeyAlgorithm get algorithm => keyPacket.algorithm;

  String get fingerprint => keyPacket.fingerprint;

  KeyID get keyID => keyPacket.keyID;

  KeyParams get publicParams => keyPacket.publicParams;

  int get keyStrength => keyPacket.keyStrength;

  PacketList toPacketList() {
    return PacketList([
      keyPacket,
      ...revocationSignatures,
      ...bindingSignatures,
    ]);
  }
}
