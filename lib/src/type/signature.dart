/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'cleartext_message.dart';
import 'key.dart';
import 'literal_data.dart';
import 'verification.dart';

/// Signature interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SignatureInterface {
  /// Get signing key IDs
  Iterable<Uint8List> get signingKeyIDs;

  /// Get verification errors
  Iterable<String> get verificationErrors;

  /// Verify signature with literal data
  /// Return verification iterable
  Iterable<VerificationInterface> verify(
    Iterable<KeyInterface> verificationKeys,
    LiteralDataInterface literalData, [
    DateTime? time,
  ]);

  /// Verify signature with cleartext
  /// Return verification iterable
  Iterable<VerificationInterface> verifyCleartext(
    Iterable<KeyInterface> verificationKeys,
    CleartextMessageInterface cleartext, [
    DateTime? time,
  ]);
}
