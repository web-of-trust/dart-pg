/// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

export 'blowfish.dart';
export 'buffered_cipher.dart';
export 'camellia.dart';
export 'cast5.dart';
export 'idea.dart';
export 'triple_des.dart';
export 'twofish.dart';

/// Base implementation of [BlockCipher] which provides shared methods.
/// Ported from Bouncy Castle project
abstract class BaseCipher implements BlockCipher {
  @override
  Uint8List process(final Uint8List data) {
    final out = Uint8List(blockSize);
    final len = processBlock(data, 0, out, 0);
    return out.sublist(0, len);
  }
}
