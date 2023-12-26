// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/hash_algorithm.dart';
import 'key_params.dart';

abstract class VerificationParams extends KeyParams {
  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  );
}
