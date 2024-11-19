/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../common/config.dart';
import '../common/helpers.dart';
import '../cryptor/symmetric/buffered_cipher.dart';
import '../enum/aead_algorithm.dart';
import '../enum/hash_algorithm.dart';
import '../enum/packet_type.dart';
import '../enum/symmetric_algorithm.dart';
import '../type/packet_list.dart';
import 'base.dart';
import 'packet_list.dart';

/// Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SymEncryptedIntegrityProtectedDataPacket extends BasePacket {
  static const saltSize = 32;
  static const mdcSuffix = [0xd3, 0x14];

  final int version;

  final Uint8List encrypted;

  final PacketListInterface? packets;

  final SymmetricAlgorithm? symmetric;

  final AeadAlgorithm? aead;

  final int chunkSize;

  final Uint8List? salt;

  SymEncryptedIntegrityProtectedDataPacket(
    this.version,
    this.encrypted, {
    this.packets,
    this.symmetric,
    this.aead,
    this.chunkSize = 0,
    this.salt,
  }) : super(PacketType.symEncryptedIntegrityProtectedData) {
    if (version != 1 && version != 2) {
      throw UnsupportedError(
        'Version $version of the SEIPD packet is unsupported.',
      );
    }

    if (symmetric != null) {
      Helper.assertSymmetric(symmetric!);
    }

    if (aead != null && version != 2) {
      throw StateError(
        'Using AEAD with version $version SEIPD packet is not allowed.',
      );
    }

    if (salt != null && salt!.length != saltSize) {
      throw StateError(
        'Salt size must be $saltSize bytes.',
      );
    }
  }

  factory SymEncryptedIntegrityProtectedDataPacket.fromBytes(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number.
    final version = bytes[pos++];

    final SymmetricAlgorithm? symmetric;
    final AeadAlgorithm? aead;
    final int chunkSize;
    final Uint8List? salt;

    if (version == 2) {
      /// A one-octet cipher algorithm.
      symmetric = SymmetricAlgorithm.values.firstWhere(
        (algo) => algo.value == bytes[pos],
      );
      pos++;

      /// A one-octet AEAD algorithm.
      aead = AeadAlgorithm.values.firstWhere(
        (algo) => algo.value == bytes[pos],
      );
      pos++;

      /// A one-octet chunk size.
      chunkSize = bytes[pos++];

      /// Thirty-two octets of salt.
      /// The salt is used to derive the message key and must be unique.
      salt = bytes.sublist(pos, pos + saltSize);
      pos += saltSize;
    } else {
      symmetric = null;
      aead = null;
      chunkSize = 0;
      salt = null;
    }
    return SymEncryptedIntegrityProtectedDataPacket(
      version,
      bytes.sublist(pos),
      symmetric: symmetric,
      aead: aead,
      chunkSize: chunkSize,
      salt: salt,
    );
  }

  factory SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
    final Uint8List key,
    final PacketListInterface packets, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final AeadAlgorithm aead = AeadAlgorithm.gcm,
    final bool aeadProtect = false,
  }) {
    Helper.assertSymmetric(symmetric);

    final version = aeadProtect ? 2 : 1;
    final salt = aeadProtect ? Helper.secureRandom().nextBytes(saltSize) : null;
    final chunkSize = aeadProtect ? Config.aeadChunkSize : 0;

    final Uint8List encrypted;
    if (aeadProtect) {
      encrypted = _aeadCrypt(
        true,
        key,
        packets.encode(),
        symmetric: symmetric,
        aead: aead,
        chunkSizeByte: chunkSize,
        salt: salt,
      );
    } else {
      final cipher = BufferedCipher(symmetric.cfbCipherEngine)
        ..init(
          true,
          ParametersWithIV(
            KeyParameter(key),
            Uint8List(symmetric.blockSize),
          ),
        );
      final toHash = Uint8List.fromList([
        ...Helper.generatePrefix(symmetric),
        ...packets.encode(),
        ...mdcSuffix,
      ]);
      encrypted = cipher.process(Uint8List.fromList([
        ...toHash,
        ...Helper.hashDigest(toHash, HashAlgorithm.sha1),
      ]));
    }

    return SymEncryptedIntegrityProtectedDataPacket(
      version,
      encrypted,
      packets: packets,
      symmetric: symmetric,
      aead: aead,
      chunkSize: chunkSize,
      salt: salt,
    );
  }

  @override
  Uint8List get data => Uint8List.fromList([
        version,
        ...symmetric != null ? [symmetric!.value] : [],
        ...aead != null ? [aead!.value] : [],
        ...chunkSize > 0 ? [chunkSize] : [],
        ...salt ?? [],
        ...encrypted,
      ]);

  /// Encrypt the payload in the packet.
  SymEncryptedIntegrityProtectedDataPacket encrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    AeadAlgorithm aead = AeadAlgorithm.gcm,
    bool aeadProtect = false,
  }) {
    if (packets != null && packets!.isNotEmpty) {
      return SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        key,
        packets!,
        symmetric: symmetric,
        aead: aead,
        aeadProtect: aeadProtect,
      );
    }
    return this;
  }

  SymEncryptedIntegrityProtectedDataPacket decrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  }) {
    if (packets != null && packets!.isNotEmpty) {
      return this;
    } else {
      final cipherSymmetric = this.symmetric ?? symmetric;
      final Uint8List packetBytes;
      if (aead != null) {
        final length = encrypted.length;
        final data = encrypted.sublist(0, length - aead!.tagLength);
        final authTag = encrypted.sublist(length - aead!.tagLength);
        packetBytes = _aeadCrypt(
          false,
          key,
          data,
          finalChunk: authTag,
          symmetric: cipherSymmetric,
          aead: aead!,
          chunkSizeByte: chunkSize,
          salt: salt,
        );
      } else {
        final cipher = BufferedCipher(cipherSymmetric.cfbCipherEngine)
          ..init(
            false,
            ParametersWithIV(
              KeyParameter(key),
              Uint8List(cipherSymmetric.blockSize),
            ),
          );
        final decrypted = cipher.process(encrypted);
        final realHash = decrypted.sublist(
          decrypted.length - HashAlgorithm.sha1.digestSize,
        );
        final toHash = decrypted.sublist(
          0,
          decrypted.length - HashAlgorithm.sha1.digestSize,
        );
        final verifyHash = realHash.equals(
          Helper.hashDigest(toHash, HashAlgorithm.sha1),
        );
        if (!verifyHash) {
          throw StateError('Modification detected.');
        }
        packetBytes = toHash.sublist(cipherSymmetric.blockSize + 2, toHash.length - 2);
      }
      return SymEncryptedIntegrityProtectedDataPacket(
        version,
        encrypted,
        packets: PacketList.decode(packetBytes),
        symmetric: cipherSymmetric,
        aead: aead,
        chunkSize: chunkSize,
        salt: salt,
      );
    }
  }

  static Uint8List _aeadCrypt(
    final bool forEncryption,
    final Uint8List key,
    final Uint8List data, {
    final Uint8List? finalChunk,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    AeadAlgorithm aead = AeadAlgorithm.gcm,
    chunkSizeByte = 0,
    final Uint8List? salt,
  }) {
    final dataLength = data.length;
    final tagLength = forEncryption ? 0 : aead.tagLength;
    final chunkSize = (1 << (chunkSizeByte + 6)) + tagLength;

    final aData = Uint8List.fromList([
      0xc0 | PacketType.symEncryptedIntegrityProtectedData.value,
      2,
      symmetric.value,
      aead.value,
      chunkSizeByte,
    ]);
    final keySize = symmetric.keySizeInByte;
    final ivLength = aead.ivLength;

    final derivedKey = Helper.hkdf(
      key,
      keySize,
      info: aData,
      salt: salt,
    );
    final kek = derivedKey.sublist(0, keySize);
    final nonce = derivedKey.sublist(keySize, keySize + ivLength);

    /// The last 8 bytes of HKDF output are unneeded, but this avoids one copy.
    nonce.setAll(ivLength - 8, List.filled(8, 0));

    final processed = dataLength - tagLength * (dataLength / chunkSize).ceil();
    final crypted = Uint8List(
      processed + (forEncryption ? aead.tagLength : 0),
    );
    final cipher = aead.cipherEngine(kek, symmetric);
    var chunkData = Uint8List.fromList(data);
    for (var chunkIndex = 0; chunkIndex == 0 || chunkData.isNotEmpty;) {
      // Take a chunk of `data`, en/decrypt it,
      // and shift `data` to the next chunk.
      final size = chunkSize < chunkData.length ? chunkSize : chunkData.length;
      crypted.setAll(
        chunkIndex * size,
        forEncryption
            ? cipher.encrypt(
                chunkData.sublist(0, size),
                nonce,
                aData,
              )
            : cipher.decrypt(
                chunkData.sublist(0, size),
                nonce,
                aData,
              ),
      );

      chunkData = chunkData.sublist(size);
      nonce.setAll(ivLength - 4, chunkIndex.pack32());
    }

    /// For encryption: empty final chunk
    /// For decryption: final authentication tag
    final aDataTag = Uint8List.fromList(
      [...aData, ...List.filled(8, 0)],
    );
    aDataTag.setAll(aDataTag.length - 4, processed.pack32());
    final finalCrypted = forEncryption
        ? cipher.encrypt(
            finalChunk ?? Uint8List(0),
            nonce,
            aDataTag,
          )
        : cipher.decrypt(
            finalChunk ?? Uint8List(0),
            nonce,
            aDataTag,
          );
    return Uint8List.fromList([...crypted, ...finalCrypted]);
  }
}
