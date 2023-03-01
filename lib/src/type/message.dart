// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../armor/armor.dart';
import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';
import '../packet/contained_packet.dart';
import '../packet/key/key_id.dart';
import '../packet/literal_data.dart';
import '../packet/one_pass_signature.dart';
import '../packet/packet_list.dart';
import '../packet/public_key_encrypted_session_key.dart';
import '../packet/signature_packet.dart';
import '../packet/sym_encrypted_integrity_protected_data.dart';
import '../packet/sym_encrypted_session_key.dart';
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

/// Class that represents an OpenPGP message.
/// Can be an encrypted message, signed message, compressed message or literal message
/// See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
class Message {
  /// The packets that form this message
  final PacketList packetList;

  Message(this.packetList);

  factory Message.createTextMessage(
    final String text, {
    final DateTime? time,
  }) =>
      Message(PacketList([LiteralDataPacket.fromText(text, time: time)]));

  factory Message.createBinaryMessage(
    final Uint8List data, {
    final String filename = '',
    final DateTime? time,
  }) =>
      Message(PacketList([
        LiteralDataPacket(
          data,
          format: LiteralFormat.binary,
          filename: filename,
          time: time,
        )
      ]));

  /// Returns ASCII armored text of message
  String armor() => Armor.encode(ArmorType.message, packetList.packetEncode());

  /// Append signature to unencrypted message
  Message appendSignature(SignaturePacket signature) {
    return Message(PacketList([...packetList, signature]));
  }

  /// Gets the key IDs of the keys that signed the message
  Iterable<KeyID> get signingKeyIDs {
    final onePassSignatures = packetList.whereType<OnePassSignaturePacket>();
    if (onePassSignatures.isNotEmpty) {
      return onePassSignatures.map((packet) => packet.issuerKeyID);
    }
    return packetList.whereType<SignaturePacket>().map((packet) => KeyID(packet.issuerKeyID.data));
  }

  /// Gets the key IDs of the keys to which the session key is encrypted
  Iterable<KeyID> get encryptionKeyIDs {
    return packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().map((packet) => packet.publicKeyID);
  }

  /// Sign the message (the literal data packet of the message)
  Message sign(
    final List<PrivateKey> signingKeys, {
    final Signature? signature,
    final DateTime? date,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to sign.');
    }

    final packets = <ContainedPacket>[];
    if (signature != null) {
      packets.addAll(signature.packets.map(
        (packet) => OnePassSignaturePacket(
          packet.signatureType,
          packet.hashAlgorithm,
          packet.keyAlgorithm,
          KeyID(packet.issuerKeyID.data),
          0,
        ),
      ));
    }

    final literalData = literalDataPackets.elementAt(0);
    final SignatureType signatureType;
    switch (literalData.format) {
      case LiteralFormat.text:
      case LiteralFormat.utf8:
        signatureType = SignatureType.text;
        break;
      default:
        signatureType = SignatureType.binary;
    }
    packets.addAll(signingKeys.map((key) {
      final index = signingKeys.indexOf(key);
      final keyPacket = key.getSigningKeyPacket(date: date);
      return OnePassSignaturePacket(
        signatureType,
        SignaturePacket.getPreferredHash(keyPacket),
        keyPacket.algorithm,
        keyPacket.keyID,
        (index == signingKeys.length - 1) ? 1 : 0,
      );
    }));
    packets.add(literalData);

    packets.addAll(signingKeys.map(
      (key) => SignaturePacket.createLiteralData(
        key.getSigningKeyPacket(),
        literalDataPackets.elementAt(0),
        date: date,
      ),
    ));
    if (signature != null) {
      packets.addAll(signature.packets);
    }

    return Message(PacketList(packets));
  }

  /// Create a detached signature for the message (the literal data packet of the message)
  Signature signDetached(
    final List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to sign.');
    }
    return Signature(
      PacketList(
        signingKeys.map(
          (key) => SignaturePacket.createLiteralData(
            key.getSigningKeyPacket(),
            literalDataPackets.elementAt(0),
            date: date,
          ),
        ),
      ),
    );
  }

  List<Verification> verify(
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }

    return Verification.createVerifications(
      literalDataPackets.elementAt(0),
      packetList.whereType<SignaturePacket>(),
      verificationKeys,
      date: date,
    );
  }

  /// Verify detached message signature
  List<Verification> verifySignature(
    final Signature signature,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }

    return Verification.createVerifications(
      literalDataPackets.elementAt(0),
      signature.packets,
      verificationKeys,
      date: date,
    );
  }

  /// Encrypt the message either with public keys, passwords, or both at once.
  /// Return new message with encrypted content.
  Message encrypt(
    final List<PublicKey> encryptionKeys, {
    final List<String> passwords = const [],
    final SymmetricAlgorithm sessionKeySymmetric = OpenPGP.preferredSymmetric,
  }) {
    if (encryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError('No encryption keys or passwords provided');
    }
    final sessionKeyData = Helper.generateEncryptionKey(sessionKeySymmetric);
    final pkeskPackets = encryptionKeys.map((key) => PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
          key.getEncryptionKeyPacket(),
          sessionKeyData: sessionKeyData,
          sessionKeySymmetric: sessionKeySymmetric,
        ));
    final skeskPackets = passwords.map((password) => SymEncryptedSessionKeyPacket.encryptSessionKey(
          password,
          sessionKeyData: sessionKeyData,
          sessionKeySymmetric: sessionKeySymmetric,
        ));
    final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
      sessionKeyData,
      packetList,
      symmetric: sessionKeySymmetric,
    );

    return Message(PacketList([
      ...pkeskPackets,
      ...skeskPackets,
      seip,
    ]));
  }

  /// Decrypt the message. Either a private key, or a password must be specified.
  /// Return new message with decrypted content.
  Message decrypt(
    final List<PrivateKey> decryptionKeys, {
    final List<String> passwords = const [],
  }) {
    if (decryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError('No decryption keys or passwords provided');
    }

    final encryptedPackets = packetList.filterByTags([
      PacketTag.symEncryptedData,
      PacketTag.symEncryptedIntegrityProtectedData,
    ]);
    if (encryptedPackets.isEmpty) {
      throw StateError('No encrypted data found');
    }

    if (decryptionKeys.isNotEmpty) {
      final pkeskPackets = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>();
    } else if (passwords.isNotEmpty) {
      final skeskPackets = packetList.whereType<SymEncryptedSessionKeyPacket>();
    }

    return Message(PacketList([]));
  }
}
