/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:pointycastle/block/modes/ecb.dart';

import '../../cryptor/symmetric/camellia.dart';
import 'key_wrapper.dart';

/// An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class CamelliaKeyWrapper extends KeyWrapper {
  CamelliaKeyWrapper(final int keySize)
      : super(
          ECBBlockCipher(CamelliaEngine()),
          keySize,
        );
}