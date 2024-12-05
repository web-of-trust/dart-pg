/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'key.dart';
import 'notation_data.dart';
import 'private_key.dart';
import 'signature.dart';
import 'signed_message.dart';
import 'verification.dart';

/// Cleartext message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class CleartextMessageInterface {
  /// Get cleartext
  String get text;

  /// Get normalized cleartext
  /// Remove trailing whitespace and
  /// normalize EOL to canonical form <CR><LF>
  String get normalizeText;

  /// Sign the message
  SignedMessageInterface sign(
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

  /// Verify detached signature & return verification array
  Iterable<VerificationInterface> verifyDetached(
    final Iterable<KeyInterface> verificationKeys,
    final SignatureInterface signature, [
    final DateTime? time,
  ]);
}
