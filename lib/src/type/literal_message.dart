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
import 'private_key.dart';
import 'signature.dart';
import 'verification.dart';

/// Literal message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class LiteralMessageInterface implements ArmorableInterface, PacketContainerInterface {
  /// Get literal data
  LiteralDataInterface get literalData;

  /// Sign the message
  LiteralMessageInterface sign(
    Iterable<PrivateKeyInterface> signingKeys, {
    Iterable<KeyInterface> recipients = const [],
    NotationDataInterface? notationData,
    DateTime? time,
  });

  /// Sign the message
  SignatureInterface signDetached(
    Iterable<PrivateKeyInterface> signingKeys, {
    Iterable<KeyInterface> recipients = const [],
    NotationDataInterface? notationData,
    DateTime? time,
  });

  /// Verify signature
  Iterable<VerificationInterface> verify(
    Iterable<KeyInterface> verificationKeys, [
    DateTime? time,
  ]);

  /// Verify detached signature & return verification array
  Iterable<VerificationInterface> verifyDetached(
    Iterable<KeyInterface> verificationKeys,
    SignatureInterface signature, [
    DateTime? time,
  ]);

  /// Encrypt the message either with public keys, passwords, or both at once.
  /// Return new message with encrypted content.
  EncryptedMessageInterface encrypt({
    Iterable<KeyInterface> encryptionKeys = const [],
    Iterable<String> passwords = const [],
    SymmetricAlgorithm? symmetric,
  });

  /// Compress the message (the literal and signature packets of the message)
  /// Return new message with compressed content.
  LiteralMessageInterface compress([CompressionAlgorithm? algorithm]);
}
