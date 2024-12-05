/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/hash_algorithm.dart';
import 'package:dart_pg/src/message/verification.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/cleartext_message.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/literal_data.dart';
import 'package:dart_pg/src/type/signature.dart';
import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/verification.dart';

/// Signature class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Signature implements SignatureInterface {
  @override
  final Iterable<SignaturePacketInterface> packets;

  Signature(this.packets);

  /// Read signature from armored string
  factory Signature.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signature) {
      throw ArgumentError('Armored text not of signature type');
    }
    return Signature(
      PacketList.decode(armor.data).whereType<SignaturePacketInterface>(),
    );
  }

  @override
  Iterable<HashAlgorithm> get hashAlgorithms => packets.map(
        (packet) => packet.hashAlgorithm,
      );

  @override
  get packetList => PacketList(packets);

  @override
  get signingKeyIDs => packets.map(
        (signature) => signature.issuerKeyID,
      );

  @override
  armor() => Armor.encode(ArmorType.signature, packetList.encode());

  @override
  Iterable<VerificationInterface> verify(
    final Iterable<KeyInterface> verificationKeys,
    final LiteralDataInterface literalData, [
    final DateTime? time,
  ]) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided.');
    }
    final verifications = <VerificationInterface>[];
    for (final packet in packets) {
      for (final key in verificationKeys) {
        final keyPacket = key.publicKey.keyPacket;
        if (packet.issuerKeyID.equals(keyPacket.keyID)) {
          var isVerified = false;
          var verificationError = '';
          try {
            isVerified = packet.verify(
              keyPacket,
              literalData.signBytes,
              time,
            );
          } on Error catch (error) {
            verificationError = error.toString();
          }

          verifications.add(Verification(
            keyPacket.keyID,
            packet,
            isVerified,
            verificationError,
          ));
        }
      }
    }
    return verifications;
  }

  @override
  verifyCleartext(
    final Iterable<KeyInterface> verificationKeys,
    final CleartextMessageInterface cleartext, [
    final DateTime? time,
  ]) {
    return verify(
      verificationKeys,
      LiteralDataPacket.fromText(cleartext.text),
      time,
    );
  }
}
