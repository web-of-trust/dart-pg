/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import '../packet/base_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature/features.dart';
import '../type/key.dart';
import '../type/key_packet.dart';
import '../type/packet_list.dart';
import '../type/signature_packet.dart';
import '../type/subkey.dart';
import '../type/subkey_packet.dart';
import '../type/user.dart';
import '../type/user_id_packet.dart';
import 'subkey.dart';
import 'user.dart';

/// Base abstract OpenPGP key class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseKey implements KeyInterface {
  @override
  late final KeyPacketInterface keyPacket;

  @override
  late final List<SignaturePacketInterface> revocationSignatures;

  @override
  late final List<SignaturePacketInterface> directSignatures;

  @override
  late final List<UserInterface> users;

  @override
  late final List<SubkeyInterface> subkeys;

  BaseKey(final PacketListInterface packetList) {
    _readPacketList(packetList);
  }

  @override
  get creationTime => keyPacket.creationTime;

  @override
  get expirationTime {
    final time = keyExpiration(directSignatures.toList());
    if (time == null) {
      for (final user in users) {
        if (user.isPrimary) {
          return keyExpiration(user.selfSignatures.toList());
        }
      }
    }
    return time;
  }

  @override
  get fingerprint => keyPacket.fingerprint;

  @override
  get keyAlgorithm => keyPacket.keyAlgorithm;

  @override
  get keyID => keyPacket.keyID;

  @override
  get keyStrength => keyPacket.keyStrength;

  @override
  get version => keyPacket.keyVersion;

  @override
  get packetList => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...directSignatures,
        ...users.map((user) => user.packetList).expand((packet) => packet),
        ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
        ...keyPacket.isV6Key
            ? [
                PaddingPacket.createPadding(
                  Helper.randomInt(
                    PaddingPacket.paddingMin,
                    PaddingPacket.paddingMax,
                  ),
                )
              ]
            : [],
      ]);

  @override
  bool get aeadSupported {
    for (final signature in directSignatures) {
      final features = signature.getSubpacket<Features>();
      if (features != null && features.supportVersion2SEIPD) {
        return true;
      }
    }
    for (final user in users) {
      if (user.isPrimary) {
        for (final signature in user.selfSignatures) {
          final features = signature.getSubpacket<Features>();
          if (features != null && features.supportVersion2SEIPD) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @override
  getEncryptionKeyPacket([final Uint8List? keyID]) {
    subkeys.sort(
      (a, b) => b.creationTime.compareTo(
        a.creationTime,
      ),
    );
    for (final subkey in subkeys) {
      if (keyID == null || subkey.keyID.equals(keyID)) {
        if (subkey.isEncryptionKey) {
          return subkey.keyPacket;
        }
      }
    }
    return null;
  }

  @override
  isRevoked({
    final KeyInterface? verifyKey,
    final SignaturePacketInterface? certificate,
    final DateTime? time,
  }) {
    if (revocationSignatures.isNotEmpty) {
      final keyID = certificate?.issuerKeyID;
      final keyPacket = verifyKey?.publicKey.keyPacket ?? publicKey.keyPacket;
      for (final signature in revocationSignatures) {
        if (keyID == null || signature.issuerKeyID.equals(keyID)) {
          if (signature.verify(keyPacket, keyPacket.signBytes, time)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @override
  isCertified(
    final KeyInterface verifyKey, {
    final SignaturePacketInterface? certificate,
    final DateTime? time,
  }) {
    for (var user in users) {
      if (user.isPrimary &&
          user.isCertified(
            verifyKey,
            certificate: certificate,
            time: time,
          )) {
        return true;
      }
    }
    return false;
  }

  @override
  verify({final String userID = '', final DateTime? time}) {
    if (userID.isEmpty) {
      for (final signature in directSignatures) {
        if (signature.verify(
          publicKey.keyPacket,
          keyPacket.signBytes,
          time,
        )) {
          return true;
        }
      }
    }
    for (var user in users) {
      if (userID.isEmpty || user.userID == userID) {
        if (user.verify(time)) {
          return true;
        }
      }
    }
    return false;
  }

  _readPacketList(final PacketListInterface packetList) {
    final keyPacketList = packetList.takeWhile(
      (packet) => packet is KeyPacketInterface,
    );

    if (keyPacketList.isEmpty) {
      throw StateError('Key packet not found in packet list.');
    }
    if (keyPacketList.length > 1) {
      throw StateError('Key block contains multiple key packets.');
    }
    keyPacket = keyPacketList.whereType<KeyPacketInterface>().first;

    var remainPackets = packetList.skipWhile(
      (packet) => packet is KeyPacketInterface,
    );

    revocationSignatures = remainPackets
        .takeWhile((packet) {
          if (packet is SignaturePacketInterface) {
            return packet.isCertRevocation;
          }
          return false;
        })
        .whereType<SignaturePacketInterface>()
        .toList();
    remainPackets = remainPackets.skipWhile((packet) {
      if (packet is SignaturePacketInterface) {
        return packet.isKeyRevocation;
      }
      return false;
    });

    directSignatures = remainPackets
        .takeWhile((packet) {
          if (packet is SignaturePacketInterface) {
            return packet.isDirectKey;
          }
          return false;
        })
        .whereType<SignaturePacketInterface>()
        .toList();
    remainPackets = remainPackets.skipWhile((packet) {
      if (packet is SignaturePacketInterface) {
        return packet.isDirectKey;
      }
      return false;
    });

    User? user;
    final users = <UserInterface>[];
    final userPackets = remainPackets.takeWhile((packet) {
      return packet is! SubkeyPacketInterface;
    });
    for (final packet in userPackets) {
      if (packet is UserIDPacketInterface) {
        user = User(
          this,
          packet,
          revocationSignatures: [],
          selfSignatures: [],
          otherSignatures: [],
        );
        users.add(user);
      }
      if (packet is SignaturePacketInterface) {
        if (packet.isCertification) {
          if (packet.issuerKeyID.equals(keyPacket.keyID)) {
            user?.selfSignatures.add(packet);
          } else {
            user?.otherSignatures.add(packet);
          }
        }
        if (packet.isCertRevocation) {
          user?.revocationSignatures.add(packet);
        }
      }
    }
    this.users = users.where((user) => user.verify()).toList();

    Subkey? subkey;
    final subkeys = <SubkeyInterface>[];
    final subkeyPackets = remainPackets.skipWhile((packet) {
      return packet is! SubkeyPacketInterface;
    });
    for (final packet in subkeyPackets) {
      if (packet is SubkeyPacketInterface) {
        subkey = Subkey(
          this,
          packet,
          revocationSignatures: [],
          bindingSignatures: [],
        );
        subkeys.add(subkey);
      }
      if (packet is SignaturePacketInterface) {
        if (packet.isSubkeyRevocation) {
          subkey?.revocationSignatures.add(packet);
        }
        if (packet.isSubkeyBinding) {
          subkey?.bindingSignatures.add(packet);
        }
      }
    }
    this.subkeys = subkeys.where((subkey) => subkey.verify()).toList();
  }

  static DateTime? keyExpiration(
    final List<SignaturePacketInterface> signatures,
  ) {
    signatures.sort(
      (a, b) => b.creationTime.compareTo(
        a.creationTime,
      ),
    );
    for (final signature in signatures) {
      if (signature.keyExpirationTime > 0) {
        final creationTime = signature.creationTime;
        return creationTime.add(Duration(
          seconds: signature.keyExpirationTime,
        ));
      } else if (signature.expirationTime != null) {
        return signature.expirationTime;
      }
    }
    return null;
  }
}
