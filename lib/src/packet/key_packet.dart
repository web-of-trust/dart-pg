// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import 'key/key_id.dart';
import 'contained_packet.dart';

abstract class KeyPacket implements ContainedPacket {
  int get version;

  DateTime get creationTime;

  int get expirationDays;

  KeyAlgorithm get algorithm;

  String get fingerprint;

  KeyID get keyID;

  int get keyStrength;
}
