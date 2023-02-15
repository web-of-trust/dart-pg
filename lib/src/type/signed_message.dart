// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/literal_data.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import 'cleartext_message.dart';
import 'public_key.dart';
import 'signature.dart';

/// Class that represents an OpenPGP cleartext signed message.
/// See {@link https://tools.ietf.org/html/rfc4880#section-7}
class SignedMessage extends CleartextMessage {
  /// The detached signature or an empty signature for unsigned messages
  final Signature signature;

  SignedMessage(super.text, this.signature);

  factory SignedMessage.fromArmored(String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signedMessage) {
      throw Exception('Armored text not of signed message type');
    }
    final packetList = PacketList.packetDecode(armor.data);
    return SignedMessage(armor.text, Signature(packetList));
  }

  List<String> get signingKeyIDs => signature.signingKeyIDs;

  /// Returns ASCII armored text of signed signature
  String armor() {
    final hashes = signature.packetList.map((packet) => (packet as SignaturePacket).hashAlgorithm.name.toLowerCase());
    return Armor.encode(
      ArmorType.signedMessage,
      signature.packetList.packetEncode(),
      text: text,
      hashAlgo: hashes.join(),
    );
  }

  /// Verify signatures of cleartext signed message
  bool verify(List<PublicKey> keys, [DateTime? date]) {
    final literalData = LiteralDataPacket(Uint8List(0), text: text);
    return false;
  }
}
