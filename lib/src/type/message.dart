// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:developer';
import 'dart:typed_data';

import '../armor/armor.dart';
import '../enum/armor_type.dart';
import '../enum/compression_algorithm.dart';
import '../enum/literal_format.dart';
import '../enum/packet_tag.dart';
import '../enum/signature_type.dart';
import '../enum/symmetric_algorithm.dart';
import '../packet/compressed_data.dart';
import '../packet/key/key_id.dart';
import '../packet/key/session_key.dart';
import '../packet/literal_data.dart';
import '../packet/one_pass_signature.dart';
import '../packet/packet_list.dart';
import '../packet/public_key_encrypted_session_key.dart';
import '../packet/signature_packet.dart';
import '../packet/sym_encrypted_data.dart';
import '../packet/sym_encrypted_integrity_protected_data.dart';
import '../packet/sym_encrypted_session_key.dart';
import 'key.dart';
import 'signature.dart';
import 'signed_message.dart';
import 'verification.dart';

/// Class that represents an OpenPGP message.
/// Can be an encrypted message, signed message, compressed message or literal message
/// See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
class Message {
  /// The packets that form this message
  final PacketList packetList;

  final List<Verification> verifications;

  Message(
    this.packetList, [
    final Iterable<Verification> verifications = const [],
  ]) : verifications = verifications.toList(growable: false);

  factory Message.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.message) {
      throw ArgumentError('Armored text not of message type');
    }
    return Message(PacketList.packetDecode(armor.data));
  }

  factory Message.fromSignedMessage(final SignedMessage signedMessage) {
    final signatures = signedMessage.signature.packets.toList(growable: false);
    return Message(PacketList([
      LiteralDataPacket.fromText(signedMessage.text),
      ...signatures.map((packet) {
        final index = signatures.indexOf(packet);
        return OnePassSignaturePacket(
          packet.signatureType,
          packet.hashAlgorithm,
          packet.keyAlgorithm,
          packet.issuerKeyID.data,
          (index == signatures.length - 1) ? 1 : 0,
        );
      }),
      ...signedMessage.signature.packets
    ]));
  }

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

  LiteralDataPacket? get literalData {
    final packets =
        unwrapCompressed().packetList.whereType<LiteralDataPacket>();
    return packets.isNotEmpty ? packets.elementAt(0) : null;
  }

  /// Gets the key IDs of the keys that signed the message
  Iterable<KeyID> get signingKeyIDs {
    final packetList = unwrapCompressed().packetList;
    final onePassSignatures = packetList.whereType<OnePassSignaturePacket>();
    if (onePassSignatures.isNotEmpty) {
      return onePassSignatures.map((packet) => KeyID(packet.issuerKeyID));
    }
    return packetList.whereType<SignaturePacket>().map(
          (packet) => KeyID(packet.issuerKeyID.data),
        );
  }

  /// Gets the key IDs of the keys to which the session key is encrypted
  Iterable<KeyID> get encryptionKeyIDs => unwrapCompressed()
      .packetList
      .whereType<PublicKeyEncryptedSessionKeyPacket>()
      .map((packet) => packet.publicKeyID);

  Iterable<SignaturePacket> get signaturePackets =>
      unwrapCompressed().packetList.whereType<SignaturePacket>();

  /// Returns ASCII armored text of message
  String armor() => Armor.encode(ArmorType.message, packetList.encode());

  /// Append signature to unencrypted message
  Message appendSignature(final SignaturePacket signature) {
    return Message(PacketList([...unwrapCompressed().packetList, signature]));
  }

  /// Sign the message (the literal data packet of the message)
  Message sign(
    final Iterable<PrivateKey> signingKeys, {
    final DateTime? date,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided');
    }
    final literalDataPackets = packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to sign.');
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

    final keyList = signingKeys.toList(growable: false);
    return Message(PacketList([
      ...keyList.map((key) {
        final index = keyList.indexOf(key);
        final keyPacket = key.getSigningKeyPacket(date: date);
        return OnePassSignaturePacket(
          signatureType,
          keyPacket.preferredHash,
          keyPacket.algorithm,
          keyPacket.keyID.bytes,
          (index == keyList.length - 1) ? 1 : 0,
        );
      }),
      literalData,
      ...keyList.map(
        (key) => SignaturePacket.createLiteralData(
          key.getSigningKeyPacket(),
          literalData,
          date: date,
        ),
      ),
    ]));
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

  /// Verify message signatures
  /// Return new message with verifications
  Message verify(
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    final packets = unwrapCompressed().packetList;
    final literalDataPackets = packets.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }

    return Message(
      packetList,
      Verification.createVerifications(
        literalDataPackets.elementAt(0),
        packets.whereType<SignaturePacket>(),
        verificationKeys,
        date: date,
      ),
    );
  }

  /// Verify detached message signature
  /// Return new message with verifications
  Message verifySignature(
    final Signature signature,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    final literalDataPackets =
        unwrapCompressed().packetList.whereType<LiteralDataPacket>();
    if (literalDataPackets.isEmpty) {
      throw StateError('No literal data packet to verify.');
    }
    return Message(
      packetList,
      Verification.createVerifications(
        literalDataPackets.elementAt(0),
        signature.packets,
        verificationKeys,
        date: date,
      ),
    );
  }

  /// Encrypt the message either with public keys, passwords, or both at once.
  /// Return new message with encrypted content.
  Message encrypt({
    final Iterable<PublicKey> encryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final SymmetricAlgorithm sessionKeySymmetric = SymmetricAlgorithm.aes256,
    final SymmetricAlgorithm encryptionKeySymmetric = SymmetricAlgorithm.aes256,
  }) {
    if (encryptionKeys.isEmpty && passwords.isEmpty) {
      throw ArgumentError('No encryption keys or passwords provided');
    }
    final sessionKey = SessionKey.produceKey(sessionKeySymmetric);

    final pkeskPackets = encryptionKeys.map(
      (key) => PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        key.getEncryptionKeyPacket(),
        sessionKey,
      ),
    );
    final skeskPackets = passwords.map(
      (password) => SymEncryptedSessionKeyPacket.encryptSessionKey(
        password,
        sessionKey,
        symmetric: encryptionKeySymmetric,
      ),
    );
    final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
      sessionKey.key,
      packetList,
      symmetric: sessionKeySymmetric,
    );

    return Message(PacketList([
      ...pkeskPackets,
      ...skeskPackets,
      seip,
    ]));
  }

  /// Decrypt the message. One of `decryptionKeys` or `passwords` must be specified.
  /// Return new message with decrypted content.
  Message decrypt({
    final Iterable<PrivateKey> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
    final bool allowUnauthenticatedMessages = false,
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

    final sessionKeys = _decryptSessionKeys(
      decryptionKeys: decryptionKeys,
      passwords: passwords,
    );
    final encryptedPacket = encryptedPackets[0];
    if (encryptedPacket is SymEncryptedIntegrityProtectedDataPacket) {
      for (var sessionKey in sessionKeys) {
        try {
          final packets = encryptedPacket
              .decrypt(sessionKey.key, symmetric: sessionKey.symmetric)
              .packets;
          if (packets != null) {
            return Message(packets);
          }
        } on Error catch (e) {
          log(e.toString(), error: e, stackTrace: e.stackTrace);
        }
      }
    } else if (encryptedPacket is SymEncryptedDataPacket) {
      for (var sessionKey in sessionKeys) {
        try {
          final packets = encryptedPacket
              .decrypt(
                sessionKey.key,
                symmetric: sessionKey.symmetric,
                allowUnauthenticatedMessages: allowUnauthenticatedMessages,
              )
              .packets;
          if (packets != null) {
            return Message(packets);
          }
        } on Error catch (e) {
          log(e.toString(), error: e, stackTrace: e.stackTrace);
        }
      }
    }
    throw StateError('Decryption failed');
  }

  /// Compress the message (the literal and -if signed- signature data packets of the message)
  /// Return new message with compressed content.
  Message compress([
    final CompressionAlgorithm algorithm = CompressionAlgorithm.uncompressed,
  ]) {
    if (algorithm != CompressionAlgorithm.uncompressed) {
      return Message(PacketList([
        CompressedDataPacket.fromPacketList(
          packetList,
          algorithm: algorithm,
        ),
      ]));
    }
    return this;
  }

  /// Unwrap compressed message
  Message unwrapCompressed() {
    final compressedPackets = packetList.whereType<CompressedDataPacket>();
    if (compressedPackets.isNotEmpty) {
      return Message(compressedPackets.elementAt(0).packets);
    }
    return this;
  }

  List<SessionKey> _decryptSessionKeys({
    final Iterable<PrivateKey> decryptionKeys = const [],
    final Iterable<String> passwords = const [],
  }) {
    final sessionKeys = <SessionKey>[];
    if (decryptionKeys.isNotEmpty) {
      final pkeskPackets =
          packetList.whereType<PublicKeyEncryptedSessionKeyPacket>();
      for (final pkesk in pkeskPackets) {
        for (final key in decryptionKeys) {
          final keyPacket = key.getDecryptionKeyPacket();
          if (keyPacket.keyID == pkesk.publicKeyID) {
            try {
              final sessionKey = pkesk
                  .decrypt(
                    key.getDecryptionKeyPacket(),
                  )
                  .sessionKey;
              if (sessionKey != null) {
                sessionKeys.add(sessionKey);
              }
            } on Error catch (e) {
              log(e.toString(), error: e, stackTrace: e.stackTrace);
            }
          }
        }
      }
    } else if (passwords.isNotEmpty) {
      final skeskPackets = packetList.whereType<SymEncryptedSessionKeyPacket>();
      for (final skesk in skeskPackets) {
        for (final password in passwords) {
          try {
            final sessionKey = skesk.decrypt(password).sessionKey;
            if (sessionKey != null) {
              sessionKeys.add(sessionKey);
            }
          } on Error catch (e) {
            log(e.toString(), error: e, stackTrace: e.stackTrace);
          }
        }
      }
    }
    if (sessionKeys.isEmpty) {
      throw StateError('Session key decryption failed.');
    }
    return sessionKeys;
  }
}
