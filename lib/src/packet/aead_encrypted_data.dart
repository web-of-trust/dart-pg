/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import '../enum/aead_algorithm.dart';
import '../enum/symmetric_algorithm.dart';
import '../type/encrypted_data_packet.dart';
import '../type/packet_list.dart';
import 'base.dart';
import 'packet_list.dart';

/// Implementation of the Symmetrically Encrypted Authenticated Encryption with
/// Additional Data (AEAD) Protected Data Packet - Type 20
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class AeadEncryptedDataPacket extends BasePacket implements EncryptedDataPacketInterface {
  static const version = 1;

  final SymmetricAlgorithm symmetric;
  final AeadAlgorithm aead;
  final int chunkSize;
  final Uint8List iv;

  @override
  final Uint8List encrypted;

  @override
  final PacketListInterface? packets;

  AeadEncryptedDataPacket(
    this.symmetric,
    this.aead,
    this.chunkSize,
    this.iv,
    this.encrypted, {
    this.packets,
  }) : super(PacketType.aeadEncryptedData);

  factory AeadEncryptedDataPacket.fromBytes(
    final Uint8List bytes,
  ) {
    var pos = 0;

    /// A one-octet version number. The only currently defined version is 1.
    final packetVersion = bytes[pos++];
    if (packetVersion != version) {
      throw UnsupportedError(
        'Version $packetVersion of the AEAD-encrypted data packet is unsupported.',
      );
    }

    /// A one-octet number describing the symmetric algorithm used.
    final symmetric = SymmetricAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    /// A one-octet number describing the aead algorithm used.
    final aead = AeadAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    final chunkSize = bytes[pos++];
    final iv = bytes.sublist(pos, pos + aead.ivLength);
    pos += aead.ivLength;

    return AeadEncryptedDataPacket(
      symmetric,
      aead,
      chunkSize,
      iv,
      bytes.sublist(pos),
    );
  }

  factory AeadEncryptedDataPacket.encryptPackets(
    final Uint8List key,
    final PacketListInterface packets, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final AeadAlgorithm aead = AeadAlgorithm.ocb,
    final int chunkSize = 12,
  }) {
    final iv = Helper.randomBytes(aead.ivLength);
    return AeadEncryptedDataPacket(
      symmetric,
      aead,
      chunkSize,
      iv,
      _crypt(
        true,
        key,
        packets.encode(),
        symmetric: symmetric,
        aead: aead,
        chunkSizeByte: chunkSize,
        iv: iv,
      ),
      packets: packets,
    );
  }

  @override
  Uint8List get data => Uint8List.fromList([
        version,
        symmetric.value,
        aead.value,
        chunkSize,
        ...iv,
        ...encrypted,
      ]);

  @override
  AeadEncryptedDataPacket encrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  }) {
    if (packets != null && packets!.isNotEmpty) {
      return AeadEncryptedDataPacket.encryptPackets(
        key,
        packets!,
        symmetric: symmetric,
        aead: aead,
        chunkSize: chunkSize,
      );
    }
    return this;
  }

  @override
  AeadEncryptedDataPacket decrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  }) {
    final length = encrypted.length;
    final data = encrypted.sublist(0, length - aead.tagLength);
    final authTag = encrypted.sublist(length - aead.tagLength);
    return AeadEncryptedDataPacket(
      symmetric,
      aead,
      chunkSize,
      iv,
      encrypted,
      packets: PacketList.decode(_crypt(
        false,
        key,
        data,
        finalChunk: authTag,
        symmetric: symmetric,
        aead: aead,
        chunkSizeByte: chunkSize,
        iv: iv,
      )),
    );
  }

  /// En/decrypt the payload.
  static Uint8List _crypt(
    bool forEncryption,
    Uint8List key,
    Uint8List data, {
    Uint8List? finalChunk,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    AeadAlgorithm aead = AeadAlgorithm.gcm,
    final chunkSizeByte = 0,
    final Uint8List? iv,
  }) {
    final cipher = aead.cipherEngine(key, symmetric);
    final dataLength = data.length;
    final tagLength = forEncryption ? 0 : aead.tagLength;
    final chunkSize = (1 << (chunkSizeByte + 6)) + tagLength;

    final adataBuffer = Uint8List(13);

    adataBuffer.setAll(
      0,
      Uint8List.fromList([
        0xc0 | PacketType.aeadEncryptedData.value,
        version,
        symmetric.value,
        aead.value,
        chunkSizeByte,
      ]),
    );

    final processed = dataLength - tagLength * (dataLength / chunkSize).ceil();
    final crypted = Uint8List(
      processed + (forEncryption ? aead.tagLength : 0),
    );
    for (var chunkIndex = 0; chunkIndex == 0 || data.isNotEmpty;) {
      /// We take a chunk of data, en/decrypt it,
      /// and shift `data` to the next chunk.
      final chunkIndexData = adataBuffer.sublist(5, 13);
      final size = chunkSize < data.length ? chunkSize : data.length;
      crypted.setAll(
        chunkIndex * size,
        forEncryption
            ? cipher.encrypt(
                data.sublist(0, size),
                cipher.getNonce(iv ?? Uint8List(aead.ivLength), chunkIndexData),
                adataBuffer,
              )
            : cipher.decrypt(
                data.sublist(0, size),
                cipher.getNonce(iv ?? Uint8List(aead.ivLength), chunkIndexData),
                adataBuffer,
              ),
      );

      data = data.sublist(size);
      adataBuffer.setAll(9, (++chunkIndex).pack32());
    }

    /// After the final chunk, we either encrypt a final, empty data
    /// chunk to get the final authentication tag or validate that final
    /// authentication tag.
    final chunkIndexData = adataBuffer.sublist(5, 13);
    final adataTagBuffer = Uint8List(21);
    adataTagBuffer.setAll(0, adataBuffer);
    adataTagBuffer.setAll(
      17,
      processed.pack32(),
    );
    final finalCrypted = forEncryption
        ? cipher.encrypt(
            finalChunk ?? Uint8List(0),
            cipher.getNonce(
              iv ?? Uint8List(aead.ivLength),
              chunkIndexData,
            ),
            adataTagBuffer,
          )
        : cipher.decrypt(
            finalChunk ?? Uint8List(0),
            cipher.getNonce(
              iv ?? Uint8List(aead.ivLength),
              chunkIndexData,
            ),
            adataTagBuffer,
          );

    return Uint8List.fromList([...crypted, ...finalCrypted]);
  }
}
