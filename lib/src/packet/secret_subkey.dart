/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/aead_algorithm.dart';
import '../enum/ecc.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_type.dart';
import '../enum/rsa_key_size.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../type/subkey_packet.dart';
import 'public_subkey.dart';
import 'secret_key.dart';

/// Implementation of the Secret Subkey (SECSUBKEY) Packet - Type 7
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SecretSubkeyPacket extends SecretKeyPacket implements SubkeyPacketInterface {
  @override
  PacketType get type => PacketType.secretSubkey;

  SecretSubkeyPacket(
    PublicSubkeyPacket super.publicKey,
    super.keyData, {
    super.s2kUsage,
    super.symmetric,
    super.aead,
    super.s2k,
    super.iv,
    super.secretKeyMaterial,
  });

  factory SecretSubkeyPacket.fromBytes(
    final Uint8List bytes,
  ) {
    final publicKey = PublicSubkeyPacket.fromBytes(bytes);
    final keyRecord = SecretKeyPacket.parseBytes(bytes, publicKey);

    return SecretSubkeyPacket(
      publicKey,
      keyRecord.keyData,
      s2kUsage: keyRecord.s2kUsage,
      symmetric: keyRecord.symmetric,
      aead: keyRecord.aead,
      s2k: keyRecord.s2k,
      iv: keyRecord.iv,
      secretKeyMaterial: keyRecord.keyMaterial,
    );
  }

  /// Generate secret subkey packet
  factory SecretSubkeyPacket.generate(
    final KeyAlgorithm algorithm, {
    final RSAKeySize rsaKeySize = RSAKeySize.normal,
    final Ecc curve = Ecc.secp521r1,
    final DateTime? date,
  }) {
    final keyMaterial = SecretKeyPacket.generateKeyMaterial(
      algorithm,
      rsaKeySize: rsaKeySize,
      curve: curve,
      date: date,
    );
    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        algorithm.keyVersion,
        date ?? DateTime.now(),
        keyMaterial.publicMaterial,
        keyAlgorithm: algorithm,
      ),
      keyMaterial.toBytes,
      secretKeyMaterial: keyMaterial,
    );
  }

  @override
  SecretSubkeyPacket encrypt(
    final String passphrase,
    final SymmetricAlgorithm symmetric, [
    final AeadAlgorithm? aead,
  ]) {
    if (secretKeyMaterial != null) {
      final record = encryptKeyMaterial(passphrase, symmetric, aead);
      return SecretSubkeyPacket(
        publicKey as PublicSubkeyPacket,
        record.cipherText,
        s2kUsage: aead != null ? S2kUsage.aeadProtect : S2kUsage.cfb,
        symmetric: symmetric,
        aead: aead,
        s2k: record.s2k,
        iv: record.iv,
        secretKeyMaterial: secretKeyMaterial,
      );
    } else {
      return this;
    }
  }

  @override
  SecretSubkeyPacket decrypt(final String passphrase) {
    if (secretKeyMaterial == null) {
      return SecretSubkeyPacket(
        publicKey as PublicSubkeyPacket,
        keyData,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
        s2k: s2k,
        iv: iv,
        secretKeyMaterial: decryptKeyData(passphrase),
      );
    } else {
      return this;
    }
  }
}
