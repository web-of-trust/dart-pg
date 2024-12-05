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
  String get normalizeText;

  /// Sign the message
  SignedMessageInterface sign(
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

  /// Verify detached signature & return verification array
  Iterable<VerificationInterface> verifyDetached(
    Iterable<KeyInterface> verificationKeys,
    SignatureInterface signature, [
    DateTime? time,
  ]);
}
