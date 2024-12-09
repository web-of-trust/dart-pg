/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'signature_packet.dart';

/// Verification interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class VerificationInterface {
  /// Get verification key ID
  Uint8List get keyID;

  /// Get signature packet
  SignaturePacketInterface get signaturePacket;

  /// Get verification error
  String get verificationError;

  /// Is verified
  bool get isVerified;

  /// Return verification user IDs
  Iterable<String> get userIDs;
}
