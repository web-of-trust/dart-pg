// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import 'public_key.dart';

class PrivateKey extends PublicKey {
  PrivateKey(
    super.keyPacket,
    super.subKeys, {
    super.directSignatures = const [],
    super.revocationSignatures = const [],
    super.users = const [],
    super.userAttributes = const [],
  });

  @override
  bool get isPrivate => true;

  @override
  String get armor => Armor.encode(
        ArmorType.privateKey,
        toPacketList().packetEncode(),
      );

  @override
  PublicKey get toPublic {
    return PublicKey(keyPacket, subKeys);
  }
}
