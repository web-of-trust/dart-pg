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
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

/// Class that represents an OpenPGP cleartext signed message.
/// See {@link https://tools.ietf.org/html/rfc4880#section-7}
class SignedMessage extends CleartextMessage {
  /// The detached signature or an empty signature for unsigned messages
  final Signature signature;

  SignedMessage(super.text, this.signature);

  factory SignedMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signedMessage) {
      throw Exception('Armored text not of signed message type');
    }
    final packetList = PacketList.packetDecode(armor.data);
    return SignedMessage(armor.text, Signature(packetList));
  }

  factory SignedMessage.signCleartext(
    final String text,
    final List<PrivateKey> signingKeys, {
    final String userID = '',
    final DateTime? date,
    final bool detached = false,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    return SignedMessage(
      text,
      Signature(
        PacketList(
          signingKeys.map(
            (key) => SignaturePacket.createLiteralData(
              key.getSigningKeyPacket(),
              LiteralDataPacket(Uint8List(0), text: text),
              userID: userID,
              date: date,
              detached: detached,
            ),
          ),
        ),
      ),
    );
  }

  List<String> get signingKeyIDs => signature.signingKeyIDs;

  /// Returns ASCII armored text of signed signature
  String armor() {
    final hashes = signature.packetList.map((packet) => (packet as SignaturePacket).hashAlgorithm.name.toUpperCase());
    return Armor.encode(
      ArmorType.signedMessage,
      signature.packetList.packetEncode(),
      text: text,
      hashAlgo: hashes.join(', '),
    );
  }

  /// Verify signatures of cleartext signed message
  List<Verification> verify(final List<PublicKey> verificationKeys, [final DateTime? date]) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided');
    }
    return [];
  }
}
