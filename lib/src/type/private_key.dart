// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../openpgp.dart';
import '../packet/contained_packet.dart';
import '../packet/key_packet_generator.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import '../packet/signature_packet.dart';
import '../packet/user_id.dart';
import 'key.dart';
import 'key_reader.dart';
import 'subkey.dart';

/// Class that represents an OpenPGP Private Key
class PrivateKey extends Key {
  PrivateKey(
    SecretKeyPacket keyPacket, {
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
    final keyReader = KeyReader.fromPacketList(packetList);
    if (keyReader.keyPacket is! SecretKeyPacket) {
      throw ArgumentError('Key packet not of secret key type');
    }
    return PrivateKey(
      keyReader.keyPacket as SecretKeyPacket,
      revocationSignatures: keyReader.revocationSignatures,
      directSignatures: keyReader.directSignatures,
      users: keyReader.users,
      subkeys: keyReader.subkeys,
    );
  }

  /// Generates a new OpenPGP key pair. Supports RSA and ECC keys.
  /// By default, primary and subkeys will be of same type.
  /// The generated primary key will have signing capabilities.
  /// By default, one subkey with encryption capabilities is also generated.
  factory PrivateKey.generate(
    final List<String> userIDs,
    final String passphrase, {
    final KeyType type = KeyType.rsa,
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveInfo curve = OpenPGP.preferredCurve,
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final String? subkeyPassphrase,
    final DateTime? date,
  }) {
    if (userIDs.isEmpty) {
      throw Exception('UserIDs are required for key generation');
    }

    final keyAlgorithm = (type == KeyType.rsa) ? KeyAlgorithm.rsaEncryptSign : KeyAlgorithm.ecdsa;
    final subkeyAlgorithm = (type == KeyType.rsa) ? KeyAlgorithm.rsaEncryptSign : KeyAlgorithm.ecdh;

    final secretKey = KeyPacketGenerator.generateSecretKey(
      keyAlgorithm,
      rsaBits: rsaBits,
      curve: curve,
      date: date,
    ).encrypt(passphrase);
    final secretSubkey = KeyPacketGenerator.generateSecretSubkey(
      subkeyAlgorithm,
      rsaBits: rsaBits,
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
        subkeySign: subkeySign,
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

  /// Creats a revocation certificate.
  SignaturePacket createRevocationSignature({
    final RevocationReasonTag reason = RevocationReasonTag.noReason,
    final String description = '',
    final DateTime? date,
  }) {
    return SignaturePacket.createKeyRevocation(
      keyPacket,
      reason: reason,
      description: description,
      date: date,
    );
  }

  SecretKeyPacket getSigningKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) {
    return keyPacket;
  }

  /// Lock a private key with the given passphrase.
  /// This method does not change the original key.
  PrivateKey encrypt(
    final String passphrase, {
    final List<String> subkeyPassphrases = const [],
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    final HashAlgorithm hash = OpenPGP.preferredHashAlgorithm,
    final S2kType type = S2kType.iterated,
  }) {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key encryption');
    }
    return PrivateKey(
      keyPacket.encrypt(
        passphrase,
        s2kUsage: s2kUsage,
        symmetricAlgorithm: symmetricAlgorithm,
        hash: hash,
        type: type,
      ),
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: subkeys.map((subkey) {
        final index = subkeys.indexOf(subkey);
        final subkeyPassphrase = (index < subkeyPassphrases.length) ? subkeyPassphrases[index] : passphrase;
        if (subkeyPassphrase.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
          return Subkey(
            (subkey.keyPacket as SecretSubkeyPacket).encrypt(
              subkeyPassphrase,
              s2kUsage: s2kUsage,
              symmetricAlgorithm: symmetricAlgorithm,
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
  PrivateKey decrypt(final String passphrase, [final List<String> subkeyPassphrases = const []]) {
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
        final subkeyPassphrase = (index < subkeyPassphrases.length) ? subkeyPassphrases[index] : passphrase;
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
