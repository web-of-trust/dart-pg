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
import '../enum/key_type.dart';
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
  factory PrivateKey.generate(
    final Iterable<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final int keyExpirationTime = 0,
    final String? subkeyPassphrase,
    final DateTime? date,
  }) {
    if (userIDs.isEmpty || passphrase.isEmpty) {
      throw ArgumentError('UserIDs and passphrase are required for key generation');
    }

    final KeyAlgorithm keyAlgorithm;
    final KeyAlgorithm subkeyAlgorithm;
    switch (type) {
      case KeyType.rsa:
        keyAlgorithm = KeyAlgorithm.rsaEncryptSign;
        subkeyAlgorithm = KeyAlgorithm.rsaEncryptSign;
        break;
      case KeyType.dsaElGamal:
        keyAlgorithm = KeyAlgorithm.dsa;
        subkeyAlgorithm = KeyAlgorithm.elgamal;
        break;
      case KeyType.ellipticCurve:
        keyAlgorithm = KeyAlgorithm.ecdsa;
        subkeyAlgorithm = KeyAlgorithm.ecdh;
        break;
    }

    final secretKey = SecretKeyPacket.generate(
      keyAlgorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: curve,
      date: date,
    ).encrypt(passphrase);
    final secretSubkey = SecretSubkeyPacket.generate(
      subkeyAlgorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: curve,
      date: date,
    ).encrypt(subkeyPassphrase ?? passphrase);

    final packets = <ContainedPacket>[secretKey];

    /// Wrap user id with certificate signature
    for (final userID in userIDs) {
      final userIDPacket = UserIDPacket(userID);
      packets.addAll([
        userIDPacket,
        SignaturePacket.createSelfCertificate(
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
      SignaturePacket.createSubkeyBinding(
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
    final packetList = PacketList([]);
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
    return PublicKey.fromPacketList((packetList));
  }

  @override
  String armor() => Armor.encode(ArmorType.privateKey, toPacketList().packetEncode());

  SecretKeyPacket getSigningKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) {
    if (!verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort((a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime));
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (subkey.isSigningKey && subkey.verify(date: date)) {
          return subkey.keyPacket as SecretKeyPacket;
        }
      }
    }
    if (!isSigningKey || (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid signing key packet.');
    }
    return keyPacket;
  }

  SecretKeyPacket getDecryptionKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) {
    if (!verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort((a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime));
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (!subkey.isSigningKey && subkey.verify(date: date)) {
          return subkey.keyPacket as SecretKeyPacket;
        }
      }
    }
    if (isSigningKey || (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid decryption key packet.');
    }
    return keyPacket;
  }

  HashAlgorithm getPreferredHash({
    final String userID = '',
    final DateTime? date,
  }) {
    final keyPacket = getSigningKeyPacket(date: date);
    switch (keyPacket.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        final oid = (keyPacket.publicParams as ECPublicParams).oid;
        final curve = CurveInfo.values.firstWhere(
          (info) => info.identifierString == oid.objectIdentifierAsString,
          orElse: () => CurveInfo.secp521r1,
        );
        return curve.hashAlgorithm;
      default:
        try {
          final user = getPrimaryUser(userID: userID, date: date);
          for (final cert in user.selfCertifications) {
            if (cert.preferredHashAlgorithms != null && cert.preferredHashAlgorithms!.preferences.isNotEmpty) {
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
  PrivateKey encrypt(
    final String passphrase, {
    final Iterable<String> subkeyPassphrases = const [],
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
    final HashAlgorithm hash = HashAlgorithm.sha256,
    final S2kType type = S2kType.iterated,
  }) {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key encryption');
    }
    return PrivateKey(
      keyPacket.encrypt(
        passphrase,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
        hash: hash,
        type: type,
      ),
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: subkeys.map((subkey) {
        final index = subkeys.indexOf(subkey);
        final subkeyPassphrase = (index < subkeyPassphrases.length) ? subkeyPassphrases.elementAt(index) : passphrase;
        if (subkeyPassphrase.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
          return Subkey(
            (subkey.keyPacket as SecretSubkeyPacket).encrypt(
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
      }).toList(growable: false),
    );
  }

  /// Unlock a private key with the given passphrase.
  /// This method does not change the original key.
  PrivateKey decrypt(final String passphrase, [final Iterable<String> subkeyPassphrases = const []]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key decryption');
    }
    return PrivateKey(
      keyPacket.decrypt(passphrase),
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: subkeys.map((subkey) {
        final index = subkeys.indexOf(subkey);
        final subkeyPassphrase = (index < subkeyPassphrases.length) ? subkeyPassphrases.elementAt(index) : passphrase;
        if (subkeyPassphrase.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
          return Subkey(
            (subkey.keyPacket as SecretSubkeyPacket).decrypt(subkeyPassphrase),
            revocationSignatures: subkey.revocationSignatures,
            bindingSignatures: subkey.bindingSignatures,
          );
        } else {
          return subkey;
        }
      }).toList(growable: false),
    );
  }
}
