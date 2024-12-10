/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/armor.dart';
import '../common/helpers.dart';
import '../enum/armor_type.dart';
import '../message/base_message.dart';
import '../packet/base_packet.dart';
import '../packet/packet_list.dart';
import '../type/encrypted_data_packet.dart';
import '../type/encrypted_message.dart';
import '../type/packet_list.dart';
import '../type/private_key.dart';
import '../type/session_key.dart';

/// OpenPGP encrypted message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class EncryptedMessage extends BaseMessage implements EncryptedMessageInterface {
  SessionKeyInterface? _sessionKey;

  EncryptedMessage(super.packetList) {
    if (packetList.whereType<EncryptedDataPacketInterface>().isEmpty) {
      throw AssertionError(
        'No encrypted data in packet list.',
      );
    }
  }

  /// Read Literal message from armored string
  factory EncryptedMessage.fromArmored(final String armored) {
    final armor = Armor.decode(armored).assertType(ArmorType.message);
    return EncryptedMessage(PacketList.decode(armor.data));
  }

  /// Decrypt symmetric session keys using private keys or passwords (not both).
  static SessionKeyInterface decryptSessionKey(
    final PacketListInterface packetList, {
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    if (decryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError(
        'No decryption keys or passwords provided.',
      );
    }
    final errors = <String>[];
    final sessionKeys = <SessionKeyInterface>[];
    if (passwords.isNotEmpty) {
      final skeskPackets = packetList.whereType<SymEncryptedSessionKeyPacket>();
      for (final skesk in skeskPackets) {
        for (final password in passwords) {
          try {
            sessionKeys.add(skesk.decrypt(password).sessionKey!);
            break;
          } on Error catch (error) {
            errors.add(error.toString());
          }
        }
      }
    }
    if (sessionKeys.isEmpty && decryptionKeys.isNotEmpty) {
      final pkeskPackets = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>();
      for (final pkesk in pkeskPackets) {
        for (final key in decryptionKeys) {
          final keyPacket = key.getDecryptionKeyPacket();
          if (keyPacket != null && pkesk.keyID.equals(keyPacket.keyID)) {
            try {
              sessionKeys.add(pkesk.decrypt(keyPacket).sessionKey!);
            } on Error catch (error) {
              errors.add(error.toString());
            }
          }
        }
      }
    }

    if (sessionKeys.isEmpty) {
      throw AssertionError(
        'Session key decryption failed.\n${errors.join('\n')}',
      );
    }
    return sessionKeys.first;
  }

  @override
  get encryptedPacket => packetList.whereType<EncryptedDataPacketInterface>().first;

  @override
  get aeadProtected => packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().firstOrNull?.aead != null;

  @override
  get sessionKey => _sessionKey;

  @override
  decrypt({
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    _sessionKey = decryptSessionKey(
      packetList,
      decryptionKeys: decryptionKeys,
      passwords: passwords,
    );

    return LiteralMessage(encryptedPacket
        .decrypt(
          _sessionKey!.encryptionKey,
          _sessionKey!.symmetric,
        )
        .packets!);
  }
}
