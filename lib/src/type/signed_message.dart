// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/signature.dart';
import 'public_key.dart';
import 'signature.dart';

/// Class that represents an OpenPGP cleartext signed message.
/// See {@link https://tools.ietf.org/html/rfc4880#section-7}
class SignedMessage {
  /// The cleartext of the signed message
  final String _text;

  /// The detached signature or an empty signature for unsigned messages
  final Signature signature;

  SignedMessage(String text, this.signature)
      : _text = text.trimRight().replaceAll(RegExp(r'\r?\n', multiLine: true), '\r\n');

  factory SignedMessage.fromArmored(String armored) {
    final unarmor = Armor.decode(armored);
    if (unarmor['type'] != ArmorType.signedMessage) {
      throw Exception('Armored text not of signed message type');
    }
    final packetList = PacketList.packetDecode(unarmor['data']);
    return SignedMessage(unarmor['text'] ?? '', Signature(packetList));
  }

  String get text => _text.replaceAll(RegExp(r'\r\n', multiLine: true), '\n');

  List<String> get signingKeyIDs => signature.signingKeyIDs;

  /// Returns ASCII armored text of signed signature
  String armor() {
    final hashes = signature.packetList.map((packet) => (packet as SignaturePacket).hashAlgorithm.name.toLowerCase());
    return Armor.encode(
      ArmorType.signedMessage,
      signature.packetList.packetEncode(),
      text: _text,
      hashAlgo: hashes.join(),
    );
  }

  /// Verify signatures of cleartext signed message
  bool verify(List<PublicKey> keys, [DateTime? date]) {
    date = date ?? DateTime.now();
    return false;
  }
}
