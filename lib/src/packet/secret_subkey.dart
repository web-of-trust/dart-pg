// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/curve_info.dart';
import '../enum/dsa_key_size.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/s2k_type.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../openpgp.dart';
import 'key/key_pair_params.dart';
import 'public_subkey.dart';
import 'secret_key.dart';
import 'subkey_packet.dart';

class SecretSubkeyPacket extends SecretKeyPacket implements SubkeyPacket {
  @override
  PacketTag get tag => PacketTag.secretSubkey;

  SecretSubkeyPacket(
    final PublicSubkeyPacket publicKey,
    final Uint8List keyData, {
    super.s2kUsage,
    super.symmetric,
    super.s2k,
    super.iv,
    super.secretParams,
  }) : super(publicKey, keyData);

  factory SecretSubkeyPacket.fromPacketData(final Uint8List bytes) {
    final secretKey = SecretKeyPacket.fromPacketData(bytes);
    return _fromSecretKey(secretKey);
  }
  factory SecretSubkeyPacket.generate(
    final KeyAlgorithm algorithm, {
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveInfo curve = OpenPGP.preferredCurve,
    final DSAKeySize dsaKeySize = DSAKeySize.l2048n224,
    final DateTime? date,
  }) {
    final keyPair = KeyPairParams.generate(
      algorithm,
      rsaBits: rsaBits,
      curve: curve,
      dsaKeySize: dsaKeySize,
    );

    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        date ?? DateTime.now(),
        keyPair.publicParams,
        algorithm: algorithm,
      ),
      keyPair.secretParams.encode(),
      secretParams: keyPair.secretParams,
    );
  }

  @override
  PublicSubkeyPacket get publicKey => super.publicKey as PublicSubkeyPacket;

  @override
  SecretSubkeyPacket encrypt(
    final String passphrase, {
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetric = OpenPGP.preferredSymmetric,
    final HashAlgorithm hash = HashAlgorithm.sha1,
    final S2kType type = S2kType.iterated,
  }) {
    if (secretParams != null) {
      return _fromSecretKey(super.encrypt(
        passphrase,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
        hash: hash,
        type: type,
      ));
    } else {
      return this;
    }
  }

  @override
  SecretSubkeyPacket decrypt(final String passphrase) {
    if (secretParams == null) {
      return _fromSecretKey(super.decrypt(passphrase));
    } else {
      return this;
    }
  }

  static SecretSubkeyPacket _fromSecretKey(final SecretKeyPacket secretKey) {
    final publicKey = secretKey.publicKey;
    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        publicKey.creationTime,
        publicKey.publicParams,
        expirationDays: publicKey.expirationDays,
        algorithm: publicKey.algorithm,
      ),
      secretKey.keyData,
      s2kUsage: secretKey.s2kUsage,
      symmetric: secretKey.symmetric,
      s2k: secretKey.s2k,
      iv: secretKey.iv,
      secretParams: secretKey.secretParams,
    );
  }
}
