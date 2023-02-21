// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'signature.dart';

/// Class that represents validity of signature.
class Verification {
  final String keyID;

  final Signature signature;

  final bool verified;

  Verification(this.keyID, this.signature, this.verified);
}
