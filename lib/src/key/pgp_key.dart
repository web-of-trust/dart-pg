// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/key_packet.dart';
import 'subkey.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
abstract class PgpKey {
  final KeyPacket keyPacket;
  final List<Subkey> subKeys = [];

  PgpKey(this.keyPacket);
}
