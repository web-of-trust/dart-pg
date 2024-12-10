/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'cleartext_message.dart';
import 'signed_message.dart';

/// Signed cleartext message interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SignedCleartextMessageInterface implements CleartextMessageInterface, SignedMessageInterface {}
