// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import 'public_key.dart';

class PublicSubkey extends PublicKey {
  PublicSubkey(
    super.version,
    super.createdTime,
    super.pgpKey, {
    super.expirationDays,
    super.algorithm,
    super.tag = PacketTag.publicSubkey,
  });
}
