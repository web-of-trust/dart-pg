// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import 'secret_key.dart';

class SecretSubkey extends SecretKey {
  SecretSubkey(
    super.publicKey,
    super.symmetricAlgorithm,
    super.s2kUsage,
    super.iv,
    super.keyData, {
    super.s2k,
    super.tag = PacketTag.secretSubkey,
  }) : super();
}
