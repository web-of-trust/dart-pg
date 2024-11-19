/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

/// Base cipher engine class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseEngine implements BlockCipher {
  @override
  Uint8List process(final Uint8List input) {
    final output = Uint8List(blockSize);
    final len = processBlock(input, 0, output, 0);
    return output.sublist(0, len);
  }

  @override
  void reset() {}
}
