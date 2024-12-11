/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/hash_algorithm.dart';
import 'armorable.dart';
import 'cleartext_message.dart';
import 'key.dart';
import 'literal_data.dart';
import 'packet_container.dart';
import 'signature_packet.dart';
import 'verification.dart';

/// Signature interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SignatureInterface
    implements ArmorableInterface, PacketContainerInterface {
  /// Get hash algorithms
  Iterable<HashAlgorithm> get hashAlgorithms;

  /// Get signing key IDs
  Iterable<Uint8List> get signingKeyIDs;

  /// Get signature packets
  Iterable<SignaturePacketInterface> get packets;

  /// Verify signature with literal data
  /// Return verification iterable
  Iterable<VerificationInterface> verify(
    final Iterable<KeyInterface> verificationKeys,
    final LiteralDataInterface literalData, [
    final DateTime? time,
  ]);

  /// Verify signature with cleartext
  /// Return verification iterable
  Iterable<VerificationInterface> verifyCleartext(
    final Iterable<KeyInterface> verificationKeys,
    final CleartextMessageInterface cleartext, [
    final DateTime? time,
  ]);
}
