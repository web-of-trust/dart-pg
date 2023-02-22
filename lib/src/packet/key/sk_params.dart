// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

export 'ecdh_sk_params.dart';
export 'elgamal_sk_params.dart';
export 'rsa_sk_params.dart';

/// Session key params
abstract class SkParams {
  Uint8List encode();
}
