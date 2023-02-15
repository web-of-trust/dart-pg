// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../openpgp.dart';
import 'public_subkey.dart';
import 'secret_key.dart';
import 'subkey_packet.dart';

class SecretSubkeyPacket extends SecretKeyPacket implements SubkeyPacket {
  SecretSubkeyPacket(
    PublicSubkeyPacket publicKey,
    Uint8List keyData, {
    super.s2kUsage,
    super.symmetricAlgorithm,
    super.s2k,
    super.iv,
    super.secretParams,
    super.tag = PacketTag.secretSubkey,
  }) : super(publicKey, keyData);

  factory SecretSubkeyPacket.fromPacketData(final Uint8List bytes) {
    final secretKey = SecretKeyPacket.fromPacketData(bytes);
    final publicKey = secretKey.publicKey;
    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        publicKey.version,
        publicKey.creationTime,
        publicKey.publicParams,
        expirationDays: publicKey.expirationDays,
        algorithm: publicKey.algorithm,
      ),
      secretKey.keyData,
      s2kUsage: secretKey.s2kUsage,
      symmetricAlgorithm: secretKey.symmetricAlgorithm,
      s2k: secretKey.s2k,
      iv: secretKey.iv,
      secretParams: secretKey.secretParams,
    );
  }

  @override
  SecretKeyPacket encrypt(
    final String passphrase, {
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    final HashAlgorithm hash = HashAlgorithm.sha1,
    final S2kType type = S2kType.iterated,
  }) {
    if (secretParams != null) {
      final secretKey = super.encrypt(
        passphrase,
        s2kUsage: s2kUsage,
        symmetricAlgorithm: symmetricAlgorithm,
        hash: hash,
        type: type,
      );
      final publicKey = secretKey.publicKey;
      return SecretSubkeyPacket(
        PublicSubkeyPacket(
          publicKey.version,
          publicKey.creationTime,
          publicKey.publicParams,
          expirationDays: publicKey.expirationDays,
          algorithm: publicKey.algorithm,
        ),
        secretKey.keyData,
        s2kUsage: secretKey.s2kUsage,
        symmetricAlgorithm: secretKey.symmetricAlgorithm,
        s2k: secretKey.s2k,
        iv: secretKey.iv,
        secretParams: secretKey.secretParams,
      );
    } else {
      return this;
    }
  }
}
