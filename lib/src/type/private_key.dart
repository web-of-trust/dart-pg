// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:developer';

import '../armor/armor.dart';
import '../enum/armor_type.dart';
import '../enum/curve_info.dart';
import '../enum/dh_key_size.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/key_generation_type.dart';
import '../enum/packet_tag.dart';
import '../enum/rsa_key_size.dart';
import '../enum/s2k_type.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../packet/contained_packet.dart';
import '../packet/key/key_params.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import '../packet/signature_packet.dart';
import '../packet/user_id.dart';
import 'key.dart';
import 'subkey.dart';

/// Class that represents an OpenPGP Private Key
class PrivateKey extends Key {
  PrivateKey(
    final SecretKeyPacket keyPacket, {
    super.users,
    super.revocationSignatures,
    super.directSignatures,
    super.subkeys,
  }) : super(keyPacket);

  /// Reads an (optionally armored) OpenPGP private key and returns a PrivateKey object
  factory PrivateKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.privateKey) {
      throw ArgumentError('Armored text not of private key type');
    }
    return PrivateKey.fromPacketList(PacketList.packetDecode(armor.data));
  }

  factory PrivateKey.fromPacketList(final PacketList packetList) {
    final keyMap = Key.readPacketList(packetList);
    if (keyMap['keyPacket'] is! SecretKeyPacket) {
      throw StateError('Key packet not of secret key type');
    }
    return PrivateKey(
      keyMap['keyPacket'] as SecretKeyPacket,
      revocationSignatures: keyMap['revocationSignatures'],
      directSignatures: keyMap['directSignatures'],
      users: keyMap['users'],
      subkeys: keyMap['subkeys'],
    );
  }

  /// Generates a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  static Future<PrivateKey> generate(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyGenerationType type = KeyGenerationType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final int keyExpirationTime = 0,
    final String? subkeyPassphrase,
    final DateTime? date,
  }) async {
    if (userIDs.isEmpty || passphrase.isEmpty) {
      throw ArgumentError(
        'UserIDs and passphrase are required for key generation',
      );
    }

    final KeyAlgorithm keyAlgorithm;
    final KeyAlgorithm subkeyAlgorithm;
    switch (type) {
      case KeyGenerationType.rsa:
        keyAlgorithm = KeyAlgorithm.rsaEncryptSign;
        subkeyAlgorithm = KeyAlgorithm.rsaEncryptSign;
        break;
      case KeyGenerationType.dsa:
        keyAlgorithm = KeyAlgorithm.dsa;
        subkeyAlgorithm = KeyAlgorithm.elgamal;
        break;
      case KeyGenerationType.ecdsa:
        keyAlgorithm = KeyAlgorithm.ecdsa;
        subkeyAlgorithm = KeyAlgorithm.ecdh;
        break;
      case KeyGenerationType.eddsa:
        keyAlgorithm = KeyAlgorithm.eddsa;
        subkeyAlgorithm = KeyAlgorithm.ecdh;
        break;
    }

    final secretKey = await SecretKeyPacket.generate(
      keyAlgorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: (type == KeyGenerationType.eddsa) ? CurveInfo.ed25519 : curve,
      date: date,
    ).then((secretKey) => secretKey.encrypt(passphrase));
    final secretSubkey = await SecretSubkeyPacket.generate(
      subkeyAlgorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: (type == KeyGenerationType.eddsa) ? CurveInfo.curve25519 : curve,
      date: date,
    ).then(
      (secretSubkey) => secretSubkey.encrypt(subkeyPassphrase ?? passphrase),
    );

    final packets = <ContainedPacket>[secretKey];

    /// Wrap user id with certificate signature
    for (final userID in userIDs) {
      final userIDPacket = UserIDPacket(userID);
      packets.addAll([
        userIDPacket,
        await SignaturePacket.createSelfCertificate(
          secretKey,
          userID: userIDPacket,
          keyExpirationTime: keyExpirationTime,
          date: date,
        )
      ]);
    }

    /// Wrap secret subkey with binding signature
    packets.addAll([
      secretSubkey,
      await SignaturePacket.createSubkeyBinding(
        secretKey,
        secretSubkey,
        keyExpirationTime: keyExpirationTime,
        date: date,
      ),
    ]);

    return PrivateKey.fromPacketList(PacketList(packets));
  }

  @override
  SecretKeyPacket get keyPacket => super.keyPacket as SecretKeyPacket;

  @override
  PublicKey get toPublic {
    final packetList = <ContainedPacket>[];
    final packets = toPacketList();
    for (final packet in packets) {
      switch (packet.tag) {
        case PacketTag.secretKey:
          if (packet is SecretKeyPacket) {
            packetList.add(packet.publicKey);
          }
          break;
        case PacketTag.secretSubkey:
          if (packet is SecretSubkeyPacket) {
            packetList.add(packet.publicKey);
          }
          break;
        default:
          packetList.add(packet);
      }
    }
    return PublicKey.fromPacketList((PacketList(packetList)));
  }

  @override
  String armor() => Armor.encode(
        ArmorType.privateKey,
        toPacketList().encode(),
      );

  Future<SecretKeyPacket> getSigningKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) async {
    if (!await verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort(
      (a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime),
    );
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (subkey.isSigningKey && await subkey.verify(date: date)) {
          return subkey.keyPacket as SecretKeyPacket;
        }
      }
    }
    if (!isSigningKey ||
        (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid signing key packet.');
    }
    return keyPacket;
  }

  Future<SecretKeyPacket> getDecryptionKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) async {
    if (!await verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort(
      (a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime),
    );
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (!subkey.isSigningKey && await subkey.verify(date: date)) {
          return subkey.keyPacket as SecretKeyPacket;
        }
      }
    }
    if (isSigningKey ||
        (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid decryption key packet.');
    }
    return keyPacket;
  }

  Future<HashAlgorithm> getPreferredHash({
    final String userID = '',
    final DateTime? date,
  }) async {
    final keyPacket = await getSigningKeyPacket(date: date);
    switch (keyPacket.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        final oid = (keyPacket.publicParams as ECPublicParams).oid;
        final curve = CurveInfo.values.firstWhere(
          (info) => info.asn1Oid == oid,
          orElse: () => CurveInfo.secp521r1,
        );
        return curve.hashAlgorithm;
      default:
        try {
          final user = await getPrimaryUser(userID: userID, date: date);
          for (final cert in user.selfCertifications) {
            if (cert.preferredHashAlgorithms != null &&
                cert.preferredHashAlgorithms!.preferences.isNotEmpty) {
              return cert.preferredHashAlgorithms!.preferences[0];
            }
          }
        } on Error catch (e) {
          log(e.toString(), error: e, stackTrace: e.stackTrace);
        }
        return HashAlgorithm.sha256;
    }
  }

  /// Lock a private key with the given passphrase.
  /// This method does not change the original key.
  Future<PrivateKey> encrypt(
    final String passphrase, {
    final Iterable<String> subkeyPassphrases = const [],
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final HashAlgorithm hash = HashAlgorithm.sha1,
    final S2kType type = S2kType.iterated,
  }) async {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key encryption');
    }
    if (!keyPacket.isDecrypted) {
      throw StateError('Private key must be decrypted before encrypting');
    }
    return PrivateKey(
      await keyPacket.encrypt(
        passphrase,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
        hash: hash,
        type: type,
      ),
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: await Future.wait(subkeys.map((subkey) async {
        final index = subkeys.indexOf(subkey);
        final subkeyPassphrase = (index < subkeyPassphrases.length)
            ? subkeyPassphrases.elementAt(index)
            : passphrase;
        if (subkeyPassphrase.isNotEmpty &&
            subkey.keyPacket is SecretSubkeyPacket) {
          return Subkey(
            await (subkey.keyPacket as SecretSubkeyPacket).encrypt(
              subkeyPassphrase,
              s2kUsage: s2kUsage,
              symmetric: symmetric,
              hash: hash,
              type: type,
            ),
            revocationSignatures: subkey.revocationSignatures,
            bindingSignatures: subkey.bindingSignatures,
          );
        } else {
          return subkey;
        }
      })),
    );
  }

  /// Unlock a private key with the given passphrase.
  /// This method does not change the original key.
  Future<PrivateKey> decrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) async {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key decryption');
    }
    final secretKey = await keyPacket.decrypt(passphrase);
    if (!secretKey.validate()) {
      throw StateError('The key parameters are not consistent');
    }
    return PrivateKey(
      secretKey,
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: await Future.wait(subkeys.map((subkey) async {
        final index = subkeys.indexOf(subkey);
        final subkeyPassphrase = (index < subkeyPassphrases.length)
            ? subkeyPassphrases.elementAt(index)
            : passphrase;
        if (subkeyPassphrase.isNotEmpty &&
            subkey.keyPacket is SecretSubkeyPacket) {
          return Subkey(
            await (subkey.keyPacket as SecretSubkeyPacket)
                .decrypt(subkeyPassphrase),
            revocationSignatures: subkey.revocationSignatures,
            bindingSignatures: subkey.bindingSignatures,
          );
        } else {
          return subkey;
        }
      })),
    );
  }

  /// Generates a new OpenPGP subkey, and returns a clone of the Key object with the new subkey added.
  Future<PrivateKey> addSubkey(
    final String passphrase, {
    final KeyAlgorithm subkeyAlgorithm = KeyAlgorithm.rsaEncryptSign,
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final DateTime? date,
  }) async {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key generation');
    }
    final secretSubkey = await SecretSubkeyPacket.generate(
      subkeyAlgorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: curve,
      date: date,
    ).then((secretSubkey) => secretSubkey.encrypt(passphrase));

    return PrivateKey.fromPacketList(PacketList([
      ...toPacketList(),
      secretSubkey,
      await SignaturePacket.createSubkeyBinding(
        keyPacket,
        secretSubkey,
        keyExpirationTime: keyExpirationTime,
        subkeySign: subkeySign,
        date: date,
      )
    ]));
  }
}
