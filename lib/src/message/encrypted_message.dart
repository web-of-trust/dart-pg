/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/message/base_message.dart';
import 'package:dart_pg/src/message/literal_message.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/type/encrypted_data_packet.dart';
import 'package:dart_pg/src/type/encrypted_message.dart';
import 'package:dart_pg/src/type/literal_message.dart';
import 'package:dart_pg/src/type/private_key.dart';
import 'package:dart_pg/src/type/session_key.dart';

/// OpenPGP encrypted message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class EncryptedMessage extends BaseMessage implements EncryptedMessageInterface {
  SessionKeyInterface? _sessionKey;

  EncryptedMessage(super.packetList);

  @override
  EncryptedDataPacketInterface get encryptedPacket {
    final packets = packetList.whereType<EncryptedDataPacketInterface>();
    if (packets.isEmpty) {
      throw StateError('No encrypted data in packet list.');
    }
    return packets.first;
  }

  @override
  SessionKeyInterface? get sessionKey => _sessionKey;

  @override
  LiteralMessageInterface decrypt({
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    if (decryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError('No decryption keys or passwords provided.');
    }
    _sessionKey = _decryptSessionKey(decryptionKeys, passwords);

    return LiteralMessage(encryptedPacket
        .decrypt(
          _sessionKey!.encryptionKey,
          _sessionKey!.symmetric,
        )
        .packets!);
  }

  SessionKeyInterface _decryptSessionKey(
    final Iterable<PrivateKeyInterface> decryptionKeys,
    final Iterable<String> passwords,
  ) {
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
      throw StateError('Session key decryption failed.\n${errors.join('\n')}');
    }
    return sessionKeys.first;
  }
}
