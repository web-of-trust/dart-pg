/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/armor.dart';
import '../enum/armor_type.dart';
import '../message/signature.dart';
import '../packet/packet_list.dart';
import '../type/key.dart';
import '../type/signature.dart';
import '../type/signature_packet.dart';
import '../type/signed_cleartext_message.dart';

import 'cleartext_message.dart';

/// Signed message class that represents an OpenPGP cleartext signed message.
/// See RFC 9580, section 7.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class SignedMessage extends CleartextMessage implements SignedCleartextMessageInterface {
  @override
  final SignatureInterface signature;

  SignedMessage(super.text, this.signature);

  /// Read signed message from armored string
  factory SignedMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signedMessage) {
      throw ArgumentError('Armored text not of signed message type');
    }
    return SignedMessage(
      armor.text,
      Signature(
        PacketList.decode(armor.data).whereType<SignaturePacketInterface>(),
      ),
    );
  }

  @override
  String armor() {
    return Armor.encode(
      ArmorType.signedMessage,
      signature.packetList.encode(),
      text: text,
      hashAlgo: signature.hashAlgorithms
          .map(
            (hash) => hash.name.toUpperCase(),
          )
          .join(', '),
    );
  }

  @override
  verify(
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]) {
    return signature.verifyCleartext(
      verificationKeys,
      this,
      time,
    );
  }
}
