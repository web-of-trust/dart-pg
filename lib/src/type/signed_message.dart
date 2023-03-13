// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enum/armor_type.dart';
import '../packet/literal_data.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import 'cleartext_message.dart';
import 'key.dart';
import 'message.dart';
import 'signature.dart';
import 'verification.dart';

/// Class that represents an OpenPGP cleartext signed message.
/// See {@link https://tools.ietf.org/html/rfc4880#section-7}
class SignedMessage extends CleartextMessage {
  /// The detached signature or an empty signature for unsigned messages
  final Signature signature;

  SignedMessage(super.text, this.signature, [super.verifications]);

  factory SignedMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signedMessage) {
      throw ArgumentError('Armored text not of signed message type');
    }
    final packetList = PacketList.packetDecode(armor.data);
    return SignedMessage(armor.text, Signature(packetList));
  }

  /// Sign a cleartext.
  factory SignedMessage.signCleartext(
    final String text,
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
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
              LiteralDataPacket.fromText(text),
              preferredHash: key.getPreferredHash(date: date),
              date: date,
            ),
          ),
        ),
      ),
    );
  }

  List<String> get signingKeyIDs => signature.signingKeyIDs;

  /// Returns ASCII armored text of signed signature
  String armor() {
    final hashes = signature.packets.map((packet) => packet.hashAlgorithm.name.toUpperCase());
    return Armor.encode(
      ArmorType.signedMessage,
      PacketList(signature.packets).encode(),
      text: text,
      hashAlgo: hashes.join(', '),
    );
  }

  /// Verify signatures of cleartext signed message
  /// Return signed message with verifications
  SignedMessage verify(
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    return SignedMessage(
      text,
      signature,
      Verification.createVerifications(
        LiteralDataPacket.fromText(text),
        signature.packets,
        verificationKeys,
        date: date,
      ),
    );
  }

  Message toMessage() {
    return Message.fromSignedMessage(this);
  }
}
