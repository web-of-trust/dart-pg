/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'key.dart';
import 'packet_container.dart';
import 'signature_packet.dart';
import 'user_id_packet.dart';

/// OpenPGP user interface
/// That represents an user ID or attribute packet and the relevant signatures.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class UserInterface implements PacketContainerInterface {
  /// Get main key
  KeyInterface get mainKey;

  /// Get user ID packet
  UserIDPacketInterface get userIDPacket;

  /// Get user ID
  String get userID;

  /// Return user is primary
  bool get isPrimary;

  /// Get revocation signatures
  Iterable<SignaturePacketInterface> get revocationSignatures;

  /// Get self signatures
  Iterable<SignaturePacketInterface> get selfSignatures;

  /// Get other signatures
  Iterable<SignaturePacketInterface> get otherSignatures;

  /// Check if a given certificate of the user is revoked
  bool isRevoked([final DateTime? time]);

  /// Verify user.
  /// Check for existence and validity of self signature.
  bool verify([final DateTime? time]);
}
