/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'armorable.dart';
import 'encrypted_data_packet.dart';
import 'literal_message.dart';
import 'packet_container.dart';
import 'private_key.dart';
import 'session_key.dart';

/// Encrypted message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class EncryptedMessageInterface
    implements ArmorableInterface, PacketContainerInterface {
  /// Return encrypted packet.
  EncryptedDataPacketInterface get encryptedPacket;

  /// Return encrypted packet is aead protected.
  bool get aeadProtected;

  /// Return session key.
  SessionKeyInterface? get sessionKey;

  /// Decrypt the message.
  /// One of `decryptionKeys` or `passwords` must be specified.
  /// Return new message with decrypted content.
  LiteralMessageInterface decrypt({
    final Iterable<PrivateKeyInterface> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  });
}
