// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../../crypto/symmetric/camellia.dart';
import 'key_wrap.dart';

/// An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class CamelliaKeyWrap extends KeyWrap {
  CamelliaKeyWrap(final int keySize)
      : super(ECBBlockCipher(CamelliaEngine()), keySize);
}
