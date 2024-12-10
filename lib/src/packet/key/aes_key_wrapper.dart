/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:pointycastle/api.dart';

import 'key_wrapper.dart';

/// An implementation of the AES Key Wrapper from the NIST Key Wrap Specification.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class AesKeyWrapper extends KeyWrapper {
  AesKeyWrapper(final int keySize)
      : super(
          BlockCipher('AES/ECB'),
          keySize,
        );
}
