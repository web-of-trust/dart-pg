/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/armor.dart';
import '../common/config.dart';
import '../enum/armor_type.dart';
import '../enum/ecc.dart';
import '../enum/key_algorithm.dart';
import '../enum/key_type.dart';
import '../enum/rsa_key_size.dart';
import '../packet/base_packet.dart';
import '../packet/packet_list.dart';
import '../type/packet.dart';
import '../type/private_key.dart';
import '../type/secret_key_packet.dart';
import 'base_key.dart';

final class PrivateKey extends BaseKey implements PrivateKeyInterface {
  PrivateKey(super.packetList);

  /// Reads an armored OpenPGP private key and returns a PrivateKey object
  factory PrivateKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored).assertType(ArmorType.privateKey);
    return PrivateKey(PacketList.decode(armor.data));
  }

  /// Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
  /// The generated primary key will have signing capabilities.
  /// One subkey with encryption capabilities is also generated if `signOnly` is false.
  factory PrivateKey.generate(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.normal,
    final Ecc curve = Ecc.secp521r1,
    final int keyExpiry = 0,
    final bool signOnly = false,
    final DateTime? time,
  }) {
    if (userIDs.isEmpty || passphrase.isEmpty) {
      throw ArgumentError(
        'UserIDs and passphrase are required for key generation',
      );
    }
    if (type == KeyType.ecc && curve == Ecc.curve25519) {
      throw UnsupportedError(
        'Ecc curve ${curve.name} is unsupported for key generation',
      );
    }
    final KeyAlgorithm keyAlgorithm = switch (type) {
      KeyType.rsa => KeyAlgorithm.rsaEncryptSign,
      KeyType.ecc => curve == Ecc.ed25519 ? KeyAlgorithm.eddsaLegacy : KeyAlgorithm.ecdsa,
      KeyType.curve25519 => KeyAlgorithm.ed25519,
      KeyType.curve448 => KeyAlgorithm.ed448,
    };

    final secretKey = SecretKeyPacket.generate(
      keyAlgorithm,
      rsaKeySize: rsaKeySize,
      curve: curve,
      time: time,
    );
    final aead = secretKey.isV6Key && Config.aeadProtect ? Config.preferredAead : null;
    final packets = <PacketInterface>[
      secretKey.encrypt(
        passphrase,
        Config.preferredSymmetric,
        aead,
      ),
    ];
    if (secretKey.isV6Key) {
      /// Wrap secret key with direct key signature
      packets.add(SignaturePacket.createDirectKeySignature(
        secretKey,
        keyExpiry: keyExpiry,
        time: time,
      ));
    }

    /// Wrap user id with certificate signature
    var index = 0;
    for (final userID in userIDs) {
      final packet = UserIDPacket(userID);
      packets.addAll([
        packet,
        SignaturePacket.createSelfCertificate(
          secretKey,
          packet,
          isPrimaryUser: index == 0,
          keyExpiry: keyExpiry,
          time: time,
        ),
      ]);
      index++;
    }

    if (!signOnly) {
      /// Generate & Wrap secret subkey with binding signature
      final KeyAlgorithm subkeyAlgorithm = switch (type) {
        KeyType.rsa => KeyAlgorithm.rsaEncryptSign,
        KeyType.ecc => KeyAlgorithm.ecdh,
        KeyType.curve25519 => KeyAlgorithm.x25519,
        KeyType.curve448 => KeyAlgorithm.x448,
      };
      final subkeyCurve = keyAlgorithm == KeyAlgorithm.eddsaLegacy ? Ecc.curve25519 : curve;
      final secretSubkey = SecretSubkeyPacket.generate(
        subkeyAlgorithm,
        rsaKeySize: rsaKeySize,
        curve: subkeyCurve,
        time: time,
      ).encrypt(passphrase, Config.preferredSymmetric, aead);
      packets.addAll([
        secretSubkey,
        SignaturePacket.createSubkeyBinding(
          secretKey,
          secretSubkey,
          keyExpiry: keyExpiry,
          time: time,
        ),
      ]);
    }

    return PrivateKey(PacketList(packets));
  }

  @override
  get secretKeyPacket => super.keyPacket as SecretKeyPacketInterface;

  @override
  get isDecrypted => secretKeyPacket.isDecrypted;

  @override
  get isEncrypted => secretKeyPacket.isEncrypted;

  @override
  get aeadProtected => secretKeyPacket.aeadProtected;

  @override
  get publicKey {
    final packets = <PacketInterface>[];
    for (final packet in packetList) {
      switch (packet.type) {
        case PacketType.secretKey:
          if (packet is SecretKeyPacket) {
            packets.add(packet.publicKey);
          }
          break;
        case PacketType.secretSubkey:
          if (packet is SecretSubkeyPacket) {
            packets.add(packet.publicKey);
          }
          break;
        default:
          packets.add(packet);
      }
    }
    return PublicKey(PacketList(packets));
  }

  @override
  getDecryptionKeyPacket([Uint8List? keyID]) => getEncryptionKeyPacket(keyID) as SecretKeyPacketInterface;

  @override
  armor() => Armor.encode(ArmorType.privateKey, packetList.encode());

  @override
  encrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key encryption.');
    }
    if (!secretKeyPacket.isDecrypted) {
      throw StateError('Private key must be decrypted before encrypting.');
    }

    final aead = aeadProtected && Config.aeadProtect ? Config.preferredAead : null;
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = subkeyPassphrases.elementAtOrNull(index) ?? passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.encrypt(
            subkeyPass,
            Config.preferredSymmetric,
            aead,
          ),
          revocationSignatures: subkey.revocationSignatures,
          bindingSignatures: subkey.bindingSignatures,
        );
      } else {
        return subkey;
      }
    });

    return PrivateKey(PacketList([
      secretKeyPacket.encrypt(
        passphrase,
        Config.preferredSymmetric,
        aead,
      ),
      ...revocationSignatures,
      ...directSignatures,
      ...users.map((user) => user.packetList).expand((packet) => packet),
      ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
    ]));
  }

  @override
  decrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key decryption,');
    }
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = subkeyPassphrases.elementAtOrNull(index) ?? passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.decrypt(subkeyPass),
          revocationSignatures: subkey.revocationSignatures,
          bindingSignatures: subkey.bindingSignatures,
        );
      } else {
        return subkey;
      }
    });
    return PrivateKey(PacketList([
      secretKeyPacket.decrypt(passphrase),
      ...revocationSignatures,
      ...directSignatures,
      ...users.map((user) => user.packetList).expand((packet) => packet),
      ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
    ]));
  }
}
