/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'hash_algorithm.dart';

/// EdDSA curves enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum EdDSACurve {
  ed25519,
  ed448;

  int get payloadSize => switch (this) {
        ed25519 => 32,
        ed448 => 57,
      };

  HashAlgorithm get hashAlgorithm => switch (this) {
        ed25519 => HashAlgorithm.sha256,
        ed448 => HashAlgorithm.sha512,
      };
}
