// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/contained_packet.dart';
import '../packet/key/key_id.dart';
import '../packet/literal_data.dart';
import '../packet/one_pass_signature.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

/// Class that represents an OpenPGP message.
/// Can be an encrypted message, signed message, compressed message or literal message
/// See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
class Message {
  /// The packets that form this message
  final PacketList packetList;

  Message(this.packetList);

  factory Message.createTextMessage(
    final String text, {
    final DateTime? time,
  }) =>
      Message(PacketList([LiteralDataPacket.fromText(text, time: time)]));

  factory Message.createBinaryMessage(
    final Uint8List data, {
    final String filename = '',
    final DateTime? time,
  }) =>
      Message(PacketList([
        LiteralDataPacket(
          data,
          format: LiteralFormat.binary,
          filename: filename,
          time: time,
        )
      ]));

  /// Returns ASCII armored text of message
  String armor() => Armor.encode(ArmorType.message, packetList.packetEncode());

  /// Append signature to unencrypted message
  Message appendSignature(SignaturePacket signature) {
    return Message(PacketList([...packetList, signature]));
  }

  /// Sign the message (the literal data packet of the message)
  Message sign(
    final List<PrivateKey> signingKeys, {
    final Signature? signature,
    final DateTime? date,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to sign.');
    }

    final packets = <ContainedPacket>[];
    if (signature != null) {
      packets.addAll(signature.packets.map(
        (packet) => OnePassSignaturePacket(
          packet.signatureType,
          packet.hashAlgorithm,
          packet.keyAlgorithm,
          KeyID(packet.issuerKeyID.data),
          0,
        ),
      ));
    }

    final literalData = literalDataPackets.elementAt(0);
    final SignatureType signatureType;
    switch (literalData.format) {
      case LiteralFormat.text:
      case LiteralFormat.utf8:
        signatureType = SignatureType.text;
        break;
      default:
        signatureType = SignatureType.binary;
    }
    packets.addAll(signingKeys.map((key) {
      final index = signingKeys.indexOf(key);
      final keyPacket = key.getSigningKeyPacket(date: date);
      return OnePassSignaturePacket(
        signatureType,
        SignaturePacket.getPreferredHash(keyPacket),
        keyPacket.algorithm,
        keyPacket.keyID,
        (index == signingKeys.length - 1) ? 1 : 0,
      );
    }));
    packets.add(literalData);

    packets.addAll(signingKeys.map(
      (key) => SignaturePacket.createLiteralData(
        key.getSigningKeyPacket(),
        literalDataPackets.elementAt(0),
        date: date,
      ),
    ));
    if (signature != null) {
      packets.addAll(signature.packets);
    }

    return Message(PacketList(packets));
  }

  /// Create a detached signature for the message (the literal data packet of the message)
  Signature signDetached(
    final List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to sign.');
    }
    return Signature(
      PacketList(
        signingKeys.map(
          (key) => SignaturePacket.createLiteralData(
            key.getSigningKeyPacket(),
            literalDataPackets.elementAt(0),
            date: date,
          ),
        ),
      ),
    );
  }

  verify(
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }

    final onePassSignatures = packetList.whereType<OnePassSignaturePacket>();
    final signatureList = packetList.whereType<SignaturePacket>();
    if (onePassSignatures.isNotEmpty && signatureList.isEmpty) {}
  }

  /// Verify detached message signature
  List<Verification> verifySignature(
    final Signature signature,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }

    final verifications = <Verification>[];
    for (final signaturePacket in signature.packets) {
      for (final key in verificationKeys) {
        try {
          final keyPacket = key.getSigningKeyPacket(keyID: signaturePacket.issuerKeyID.keyID);
          verifications.add(Verification(
            keyPacket.keyID.keyID,
            Signature(PacketList([signaturePacket])),
            signaturePacket.verifyLiteralData(
              keyPacket,
              literalDataPackets.elementAt(0),
              date: date,
            ),
          ));
        } catch (_) {}
      }
    }

    return verifications;
  }

  static encryptSessionKey(
    final Uint8List sessionKey,
    final SymmetricAlgorithm symmetric,
    final List<PublicKey> encryptionKeys, {
    final String? passwords,
    final DateTime? date,
  }) {}
}
