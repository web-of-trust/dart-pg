// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'ec_public_params.dart';

class ECDsaPublicParams extends ECPublicParams {
  ECDsaPublicParams(super.publicKey);

  factory ECDsaPublicParams.fromPacketData(Uint8List bytes) =>
      ECDsaPublicParams(ECPublicParams.publicKeyPacketData(bytes));
}
