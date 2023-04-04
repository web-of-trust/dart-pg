// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../../crypto/symmetric/camellia.dart';
import 'key_wrap.dart';

/// An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
class CamelliaKeyWrap extends KeyWrap {
  CamelliaKeyWrap() : super(ECBBlockCipher(CamelliaEngine()));
}
