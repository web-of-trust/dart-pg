/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'armorable.dart';
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

/// Signed message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SignedMessageInterface implements ArmorableInterface {
  /// Get signature of signed message
  SignatureInterface get signature;

  /// Verify signature of signed message
  /// Return verification iterable
  Iterable<VerificationInterface> verify(
    Iterable<KeyInterface> verificationKeys, [
    DateTime? time,
  ]);
}
