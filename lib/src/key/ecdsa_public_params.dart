// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'ec_public_params.dart';

class ECDSAPublicParams extends ECPublicParams {
  ECDSAPublicParams(super.publicKey);

  factory ECDSAPublicParams.fromPacketData(Uint8List bytes) =>
      ECDSAPublicParams(ECPublicParams.publicKeyPacketData(bytes));
}
