// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// packet giving the issuer key ID.
class IssuerKeyID extends SignatureSubpacket {
  IssuerKeyID(Uint8List data, {super.critical, super.isLongLength}) : super(SignatureSubpacketType.issuerKeyID, data);

  factory IssuerKeyID.fromKeyID(int keyID, {bool critical = false}) =>
      IssuerKeyID(keyID.unpack64(), critical: critical);

  int get keyID => data.toInt64();
}
