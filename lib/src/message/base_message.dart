/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/armor.dart';
import '../common/config.dart';
import '../enum/armor_type.dart';
import '../enum/symmetric_algorithm.dart';
import '../packet/key/session_key.dart';
import '../type/armorable.dart';
import '../type/key.dart';
import '../type/packet_container.dart';
import '../type/packet_list.dart';
import '../type/session_key.dart';

/// Base abstract OpenPGP message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseMessage implements ArmorableInterface, PacketContainerInterface {
  @override
  final PacketListInterface packetList;

  BaseMessage(this.packetList);

  @override
  armor() => Armor.encode(ArmorType.message, packetList.encode());

  static SessionKeyInterface generateSessionKey(
    final Iterable<KeyInterface> encryptionKeys, [
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    var aeadProtect = Config.aeadProtect;
    final aead = Config.preferredAead;
    for (final key in encryptionKeys) {
      if (key.aeadSupported) {
        if (!key.isPreferredAeadCiphers(symmetric, aead)) {
          throw StateError('Symmetric and aead not compatible with the given `encryptionKeys`');
        }
      } else {
        if (key.preferredSymmetrics.isNotEmpty && !key.preferredSymmetrics.contains(symmetric)) {
          throw StateError('Symmetric not compatible with the given `encryptionKeys`');
        }
        aeadProtect = false;
      }
    }
    return SessionKey.produceKey(
      symmetric,
      aeadProtect ? aead : null,
    );
  }
}
