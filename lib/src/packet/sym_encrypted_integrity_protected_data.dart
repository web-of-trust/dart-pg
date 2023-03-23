// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../crypto/math/byte_ext.dart';
import '../crypto/symmetric/base_cipher.dart';
import '../enum/hash_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'packet_list.dart';

/// Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
/// See RFC 4880, section 5.13.
///
/// The Symmetrically Encrypted Integrity Protected Data packet is a variant of the Symmetrically Encrypted Data packet.
/// It is a new feature created for OpenPGP that addresses the problem of detecting a modification to encrypted data.
/// It is used in combination with a Modification Detection Code packet.
class SymEncryptedIntegrityProtectedDataPacket extends ContainedPacket {
  static const version = 1;

  /// Encrypted data, the output of the selected symmetric-key cipher
  /// operating in Cipher Feedback mode with shift amount equal to the
  /// block size of the cipher (CFB-n where n is the block size).
  final Uint8List encrypted;

  /// Decrypted packets contained within.
  final PacketList? packets;

  SymEncryptedIntegrityProtectedDataPacket(this.encrypted, {this.packets})
      : super(PacketTag.symEncryptedIntegrityProtectedData);

  factory SymEncryptedIntegrityProtectedDataPacket.fromByteData(
    final Uint8List bytes,
  ) {
    /// A one-octet version number. The only currently defined version is 1.
    final seipVersion = bytes[0];
    if (seipVersion != version) {
      throw UnsupportedError(
          'Version $seipVersion of the SEIP packet is unsupported.');
    }
    return SymEncryptedIntegrityProtectedDataPacket(bytes.sublist(1));
  }

  static Future<SymEncryptedIntegrityProtectedDataPacket> encryptPackets(
    final Uint8List key,
    final PacketList packets, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
  }) async {
    final toHash = Uint8List.fromList([
      ...Helper.generatePrefix(symmetric),
      ...packets.encode(),
      0xd3,
      0x14,
    ]);
    final plainText = Uint8List.fromList([
      ...toHash,
      ...Helper.hashDigest(toHash, HashAlgorithm.sha1),
    ]);

    final cipher = BufferedCipher(symmetric.cipherEngine)
      ..init(
        true,
        ParametersWithIV(KeyParameter(key), Uint8List(symmetric.blockSize)),
      );
    return SymEncryptedIntegrityProtectedDataPacket(
      cipher.process(plainText),
      packets: packets,
    );
  }

  @override
  Uint8List toByteData() {
    return Uint8List.fromList([version, ...encrypted]);
  }

  /// Encrypt the payload in the packet.
  Future<SymEncryptedIntegrityProtectedDataPacket> encrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
  }) async {
    if (packets != null && packets!.isNotEmpty) {
      return SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        key,
        packets!,
        symmetric: symmetric,
      );
    }
    return this;
  }

  /// Decrypts the encrypted data contained in the packet.
  Future<SymEncryptedIntegrityProtectedDataPacket> decrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
  }) async {
    final cipher = BufferedCipher(symmetric.cipherEngine)
      ..init(
        false,
        ParametersWithIV(KeyParameter(key), Uint8List(symmetric.blockSize)),
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

    return SymEncryptedIntegrityProtectedDataPacket(
      encrypted,
      packets: PacketList.packetDecode(
        toHash.sublist(symmetric.blockSize + 2, toHash.length - 2),
      ),
    );
  }
}
