/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/common/config.dart';
import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/compression_algorithm.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/message/base_message.dart';
import 'package:dart_pg/src/message/encrypted_message.dart';
import 'package:dart_pg/src/message/signature.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/key/session_key.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/literal_data.dart';
import 'package:dart_pg/src/type/literal_message.dart';
import 'package:dart_pg/src/type/notation_data.dart';
import 'package:dart_pg/src/type/packet_list.dart';
import 'package:dart_pg/src/type/private_key.dart';
import 'package:dart_pg/src/type/signature.dart';
import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/signed_message.dart';
import 'package:dart_pg/src/type/verification.dart';

/// OpenPGP literal message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class LiteralMessage extends BaseMessage implements LiteralMessageInterface, SignedMessageInterface {
  LiteralMessage(super.packetList) {
    if (packetList.whereType<LiteralDataInterface>().isEmpty) {
      throw StateError('No literal data in packet list.');
    }
  }

  /// Read Literal message from armored string
  factory LiteralMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.message) {
      throw ArgumentError('Armored text not of message type');
    }
    return LiteralMessage(PacketList.decode(armor.data));
  }

  factory LiteralMessage.fromLiteralData(
    final Uint8List literalData, {
    final String filename = '',
    final DateTime? time,
  }) {
    return LiteralMessage(PacketList([
      LiteralDataPacket(
        literalData,
        filename: filename,
        time: time,
      )
    ]));
  }

  @override
  get literalData => packetList.whereType<LiteralDataInterface>().first;

  @override
  get signature => Signature(
        unwrapCompressed().whereType<SignaturePacketInterface>(),
      );

  @override
  compress([final CompressionAlgorithm? algorithm]) {
    final algo = algorithm ?? Config.preferredCompression;
    if (algo != CompressionAlgorithm.uncompressed) {
      return LiteralMessage(
        PacketList(
          [
            CompressedDataPacket.fromPacketList(
              packetList,
              algorithm: algo,
            )
          ],
        ),
      );
    }
    return this;
  }

  @override
  encrypt({
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final SymmetricAlgorithm? symmetric,
  }) {
    if (encryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError('No encryption keys or passwords provided.');
    }
    var addPadding = false;
    var aeadSupported = Config.aeadSupported;
    for (final key in encryptionKeys) {
      if (!key.aeadSupported) {
        aeadSupported = false;
      }
      if (key.keyPacket.isV6Key) {
        addPadding = true;
      }
    }
    final sessionKey = SessionKey.produceKey(
      symmetric ?? Config.preferredSymmetric,
    );

    final packetList = addPadding
        ? PacketList([
            ...this.packetList.packets,
            PaddingPacket.createPadding(
              Helper.randomInt(
                PaddingPacket.paddingMin,
                PaddingPacket.paddingMax,
              ),
            ),
          ])
        : this.packetList;

    return EncryptedMessage(PacketList([
      ...encryptionKeys.map(
        (key) => PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
          key.publicKey.getEncryptionKeyPacket()!,
          sessionKey,
        ),
      ),
      ...passwords.map((password) => SymEncryptedSessionKeyPacket.encryptSessionKey(
            password,
            sessionKey: sessionKey,
            symmetric: symmetric ?? Config.preferredSymmetric,
            aead: Config.preferredAead,
            aeadProtect: aeadSupported && Config.aeadProtect,
          )),
      SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        sessionKey.encryptionKey,
        packetList,
        symmetric: symmetric ?? Config.preferredSymmetric,
        aead: Config.preferredAead,
        aeadProtect: aeadSupported && Config.aeadProtect,
      ),
    ]));
  }

  @override
  sign(
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    final signaturePackets = [
      ...unwrapCompressed().whereType<SignaturePacketInterface>(),
      ...signDetached(
        signingKeys,
        recipients: recipients,
        notationData: notationData,
        time: time,
      ).packets,
    ];
    var index = 0;
    final opsPackets = signaturePackets
        .map((packet) {
          return OnePassSignaturePacket.fromSignature(
            packet,
            (0 == index++) ? 1 : 0,
          );
        })
        .toList()
        .reversed; // innermost OPS refers to the first signature packet

    return LiteralMessage(PacketList([
      ...opsPackets,
      literalData,
      ...signaturePackets,
    ]));
  }

  @override
  signDetached(
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided.');
    }
    return Signature(signingKeys.map((signKey) {
      return SignaturePacket.createLiteralData(
        signKey.secretKeyPacket,
        literalData,
        recipients: recipients,
        notationData: notationData,
        time: time,
      );
    }));
  }

  @override
  Iterable<VerificationInterface> verify(
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]) {
    return signature.verify(
      verificationKeys,
      literalData,
      time,
    );
  }

  @override
  verifyDetached(
    final Iterable<KeyInterface> verificationKeys,
    final SignatureInterface signature, [
    final DateTime? time,
  ]) {
    return signature.verify(
      verificationKeys,
      literalData,
      time,
    );
  }

  PacketListInterface unwrapCompressed() {
    return packetList.whereType<CompressedDataPacket>().firstOrNull?.packets ?? packetList;
  }
}
