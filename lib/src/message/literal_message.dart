/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/armor.dart';
import '../common/config.dart';
import '../common/helpers.dart';
import '../enum/armor_type.dart';
import '../enum/compression_algorithm.dart';
import '../enum/preset_rfc.dart';
import '../enum/symmetric_algorithm.dart';
import '../message/base_message.dart';
import '../packet/base_packet.dart';
import '../packet/key/session_key.dart';
import '../type/key.dart';
import '../type/literal_data.dart';
import '../type/literal_message.dart';
import '../type/packet_list.dart';
import '../type/session_key.dart';
import '../type/signature_packet.dart';

/// OpenPGP literal message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class LiteralMessage extends BaseMessage implements LiteralMessageInterface, SignedMessageInterface {
  LiteralMessage(super.packetList) {
    if (_unwrapCompressed().whereType<LiteralDataInterface>().isEmpty) {
      throw AssertionError(
        'No literal data in packet list.',
      );
    }
  }

  /// Read Literal message from armored string
  factory LiteralMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored).assertType(ArmorType.message);
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

  /// Generate a new session key object.
  /// Checking the algorithm preferences of the passed encryption keys.
  static SessionKeyInterface generateSessionKey(
    final Iterable<KeyInterface> encryptionKeys, [
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    var aeadProtect = Config.aeadProtect;
    final aead = Config.preferredAead;
    for (final key in encryptionKeys) {
      if (key.aeadSupported) {
        if (!key.isPreferredAeadCiphers(symmetric, aead)) {
          throw AssertionError(
            'Aead ciphers not compatible with the given `encryptionKeys`',
          );
        }
      } else {
        if (key.preferredSymmetrics.isNotEmpty && !key.preferredSymmetrics.contains(symmetric)) {
          throw AssertionError(
            'Symmetric not compatible with the given `encryptionKeys`',
          );
        }
        aeadProtect = false;
      }
    }
    return SessionKey.produceKey(
      symmetric,
      aeadProtect ? aead : null,
    );
  }

  /// Encrypt a session key either with public keys, passwords, or both at once.
  static PacketListInterface encryptSessionKey(
    SessionKeyInterface sessionKey, {
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    if (encryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError(
        'No encryption keys or passwords provided.',
      );
    }
    return PacketList([
      ...encryptionKeys.map(
        (key) => PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
          key.publicKey.getEncryptionKeyPacket()!,
          sessionKey,
        ),
      ),
      ...passwords.map((password) => SymEncryptedSessionKeyPacket.encryptSessionKey(
            password,
            sessionKey: sessionKey,
            symmetric: sessionKey.symmetric,
            aead: sessionKey.aead,
          )),
    ]);
  }

  @override
  get literalData => _unwrapCompressed().whereType<LiteralDataInterface>().first;

  @override
  get signature => Signature(
        _unwrapCompressed().whereType<SignaturePacketInterface>(),
      );

  @override
  compress([final CompressionAlgorithm? algorithm]) {
    final algo = algorithm ?? Config.preferredCompression;
    if (algo != CompressionAlgorithm.uncompressed) {
      return LiteralMessage(
        PacketList(
          [
            CompressedDataPacket.fromPacketList(
              _unwrapCompressed(),
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
      throw ArgumentError(
        'No encryption keys or passwords provided.',
      );
    }
    var addPadding = Config.presetRfc == PresetRfc.rfc9580;
    for (final key in encryptionKeys) {
      if (!key.keyPacket.isV6Key) {
        addPadding = false;
      }
    }
    final sessionKey = generateSessionKey(
      encryptionKeys,
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
      ...encryptSessionKey(
        sessionKey,
        encryptionKeys: encryptionKeys,
        passwords: passwords,
      ),
      SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        sessionKey.encryptionKey,
        packetList,
        symmetric: symmetric ?? Config.preferredSymmetric,
        aead: sessionKey.aead,
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
      ..._unwrapCompressed().whereType<SignaturePacketInterface>(),
      ...signDetached(
        signingKeys,
        recipients: recipients,
        notationData: notationData,
        time: time,
      ).packets,
    ];
    var index = 0;
    /// innermost OPS refers to the first signature packet
    final opsPackets = signaturePackets
        .map((packet) {
          return OnePassSignaturePacket.fromSignature(
            packet,
            (0 == index++) ? 1 : 0,
          );
        })
        .toList()
        .reversed;

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

  PacketListInterface _unwrapCompressed() {
    return packetList.whereType<CompressedDataPacket>().firstOrNull?.packets ?? packetList;
  }
}
