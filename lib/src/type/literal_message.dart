/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../enum/compression_algorithm.dart';
import '../enum/symmetric_algorithm.dart';
import 'armorable.dart';
import 'encrypted_message.dart';
import 'key.dart';
import 'literal_data.dart';
import 'notation_data.dart';
import 'packet_container.dart';
import 'signature.dart';
import 'verification.dart';

export 'encrypted_message.dart';
export 'notation_data.dart';
export 'signature.dart';
export 'signed_message.dart';
export 'verification.dart';

/// Literal message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class LiteralMessageInterface implements ArmorableInterface, PacketContainerInterface {
  /// Get literal data
  LiteralDataInterface get literalData;

  /// Sign the message
  LiteralMessageInterface sign(
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  });

  /// Sign the message
  SignatureInterface signDetached(
    final Iterable<PrivateKeyInterface> signingKeys, {
    final Iterable<KeyInterface> recipients = const [],
    final NotationDataInterface? notationData,
    final DateTime? time,
  });

  /// Verify signature
  Iterable<VerificationInterface> verify(
    final Iterable<KeyInterface> verificationKeys, [
    final DateTime? time,
  ]);

  /// Verify detached signature & return verification array
  Iterable<VerificationInterface> verifyDetached(
    final Iterable<KeyInterface> verificationKeys,
    final SignatureInterface signature, [
    final DateTime? time,
  ]);

  /// Encrypt the message either with public keys, passwords, or both at once.
  /// Return new message with encrypted content.
  EncryptedMessageInterface encrypt({
    final Iterable<KeyInterface> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  });

  /// Compress the message (the literal and signature packets of the message)
  /// Return new message with compressed content.
  LiteralMessageInterface compress([
    final CompressionAlgorithm algorithm = CompressionAlgorithm.uncompressed,
  ]);
}
