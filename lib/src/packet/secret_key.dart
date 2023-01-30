// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart' as pc;

import '../enums.dart';
import '../helpers.dart';
import '../key/dsa_secret_pgp_key.dart';
import '../key/ec_secret_pgp_key.dart';
import '../key/elgamal_secret_pgp_key.dart';
import '../key/pgp_key.dart';
import '../key/rsa_secret_pgp_key.dart';
import '../key/s2k.dart';
import 'contained_packet.dart';
import 'public_key.dart';

/// SecretKey represents a possibly encrypted private key.
/// See RFC 4880, section 5.5.3.
class SecretKey extends ContainedPacket {
  final PublicKey publicKey;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2kUsage s2kUsage;

  final S2K? s2k;

  final Uint8List iv;

  final Uint8List keyData;

  SecretKey(
    this.publicKey,
    this.symmetricAlgorithm,
    this.s2kUsage,
    this.iv,
    this.keyData, {
    this.s2k,
    super.tag = PacketTag.secretKey,
  });

  factory SecretKey.fromPacketData(final Uint8List bytes) {
    final publicKey = PublicKey.fromPacketData(bytes);
    final length = publicKey.toPacketData().length;

    var pos = length;
    final s2kUsage = S2kUsage.values.firstWhere((usage) => usage.value == bytes[pos++]);

    final S2K? s2k;
    final SymmetricAlgorithm symmetricAlgorithm;
    switch (s2kUsage) {
      case S2kUsage.checksum:
      case S2kUsage.sha1:
        symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((usage) => usage.value == bytes[pos++]);
        s2k = S2K.fromPacketData(bytes.sublist(pos));
        break;
      default:
        symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((usage) => usage.value == s2kUsage.value);
        s2k = null;
    }
    if (s2k != null) {
      pos += s2k.encode().length;
    }

    final List<int> iv = [];
    final List<int> keyData = [];
    if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      if (symmetricAlgorithm.value < 7) {
        iv.addAll(bytes.sublist(pos, pos + 8));
        pos += 8;
      } else {
        iv.addAll(bytes.sublist(pos, pos + 16));
        pos += 16;
      }
    }
    keyData.addAll(bytes.sublist(pos));

    return SecretKey(
      publicKey,
      symmetricAlgorithm,
      s2kUsage,
      Uint8List.fromList(iv),
      Uint8List.fromList(keyData),
      s2k: s2k,
    );
  }

  bool get encrypted => s2kUsage != S2kUsage.none;

  bool get isDummy => s2k != null && s2k!.type == S2kType.gnu;

  PgpKey decrypt(String passphrase) {
    final Uint8List clearText;
    if (encrypted) {
      final key = s2k!.produceKey(passphrase, symmetricAlgorithm);
      final cipher = pc.BlockCipher('AES/CFB-128');
      cipher.init(false, pc.ParametersWithIV(pc.KeyParameter(key), iv));
      final clearTextWithHash = cipher.process(keyData);
      final hashLen = 20;
      clearText = clearTextWithHash.sublist(0, clearTextWithHash.length - hashLen);
      final hashText = clearTextWithHash.sublist(clearTextWithHash.length - hashLen);
      final digest = pc.Digest('SHA-1');
      final hash = digest.process(clearText);
      if (!hash.equals(hashText)) {
        throw Exception('Incorrect key passphrase');
      }
    } else {
      clearText = keyData;
    }

    final PgpKey pgpKey;
    switch (publicKey.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        pgpKey = RSASecretBcpgKey.fromPacketData(clearText);
        break;
      case KeyAlgorithm.elgamal:
        pgpKey = ElGamalSecretPgpKey.fromPacketData(clearText);
        break;
      case KeyAlgorithm.dsa:
        pgpKey = DSASecretPgpKey.fromPacketData(clearText);
        break;
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
        pgpKey = ECSecretPgpKey.fromPacketData(clearText);
        break;
      default:
        throw UnsupportedError('Unknown PGP public key algorithm encountered');
    }
    return pgpKey;
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [...publicKey.toPacketData(), s2kUsage.value];
    if ((s2kUsage == S2kUsage.checksum || s2kUsage == S2kUsage.sha1) && s2k != null) {
      bytes.addAll([symmetricAlgorithm.value, ...s2k!.encode()]);
    }
    bytes.addAll([...iv, ...keyData]);
    return Uint8List.fromList(bytes);
  }
}
