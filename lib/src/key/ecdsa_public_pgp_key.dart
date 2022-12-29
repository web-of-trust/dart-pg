// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'ec_public_pgp_key.dart';

class ECDsaPublicPgpKey extends ECPublicPgpKey {
  ECDsaPublicPgpKey(super.publicKey);

  factory ECDsaPublicPgpKey.fromPacketData(Uint8List bytes) =>
      ECDsaPublicPgpKey(ECPublicPgpKey.publicKeyPacketData(bytes));
}
