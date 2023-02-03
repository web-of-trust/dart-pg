// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/key/key_id.dart';
import 'package:pointycastle/block/modes/cfb.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import '../crypto/symmetric/blowfish.dart';
import '../crypto/symmetric/buffered_cipher.dart';
import '../crypto/symmetric/camellia.dart';
import '../crypto/symmetric/cast5.dart';
import '../crypto/symmetric/idea.dart';
import '../crypto/symmetric/triple_des.dart';
import '../crypto/symmetric/twofish.dart';
import '../enums.dart';
import '../helpers.dart';
import '../key/dsa_secret_params.dart';
import '../key/ec_secret_params.dart';
import '../key/elgamal_secret_params.dart';
import '../key/key_params.dart';
import '../key/rsa_secret_params.dart';
import '../key/s2k.dart';
import 'contained_packet.dart';
import 'key_packet.dart';
import 'public_key.dart';

/// SecretKey represents a possibly encrypted private key.
/// See RFC 4880, section 5.5.3.
class SecretKeyPacket extends ContainedPacket implements KeyPacket {
  final PublicKeyPacket publicKey;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2kUsage s2kUsage;

  final S2K? s2k;

  final Uint8List iv;

  final Uint8List keyData;

  SecretKeyPacket(
    this.publicKey,
    this.symmetricAlgorithm,
    this.s2kUsage,
    this.iv,
    this.keyData, {
    this.s2k,
    super.tag = PacketTag.secretKey,
  });

  factory SecretKeyPacket.fromPacketData(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromPacketData(bytes);
    final length = publicKey.toPacketData().length;

    var pos = length;
    final s2kUsage = S2kUsage.values.firstWhere((usage) => usage.value == bytes[pos]);
    pos++;

    final S2K? s2k;
    final SymmetricAlgorithm symmetricAlgorithm;
    switch (s2kUsage) {
      case S2kUsage.checksum:
      case S2kUsage.sha1:
        symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((usage) => usage.value == bytes[pos]);
        pos++;
        s2k = S2K.fromPacketData(bytes.sublist(pos));
        break;
      default:
        symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((usage) => usage.value == s2kUsage.value);
        s2k = null;
    }
    if (s2k != null) {
      pos += s2k.encode().length;
    }

    final Uint8List iv;
    if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      if (symmetricAlgorithm.value < 7) {
        iv = bytes.sublist(pos, pos + 8);
        pos += 8;
      } else {
        iv = bytes.sublist(pos, pos + 16);
        pos += 16;
      }
    } else {
      iv = Uint8List(0);
    }

    return SecretKeyPacket(
      publicKey,
      symmetricAlgorithm,
      s2kUsage,
      iv,
      bytes.sublist(pos),
      s2k: s2k,
    );
  }

  bool get encrypted => s2kUsage != S2kUsage.none;

  bool get isDummy => s2k != null && s2k!.type == S2kType.gnu;

  KeyParams decrypt(String passphrase) {
    final Uint8List clearText;
    if (encrypted) {
      final pc.BlockCipher engine;
      switch (symmetricAlgorithm) {
        case SymmetricAlgorithm.aes128:
        case SymmetricAlgorithm.aes192:
        case SymmetricAlgorithm.aes256:
          engine = pc.BlockCipher('AES/CFB-${symmetricAlgorithm.keySize}');
          break;
        case SymmetricAlgorithm.blowfish:
          engine = CFBBlockCipher(BlowfishEngine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        case SymmetricAlgorithm.camellia128:
        case SymmetricAlgorithm.camellia192:
        case SymmetricAlgorithm.camellia256:
          engine = CFBBlockCipher(CamelliaEngine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        case SymmetricAlgorithm.cast5:
          engine = CFBBlockCipher(CAST5Engine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        case SymmetricAlgorithm.idea:
          engine = CFBBlockCipher(IDEAEngine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        case SymmetricAlgorithm.tripledes:
          engine = CFBBlockCipher(TripleDESEngine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        case SymmetricAlgorithm.twofish:
          engine = CFBBlockCipher(TwofishEngine(), symmetricAlgorithm.keySize ~/ 8);
          break;
        default:
          throw UnsupportedError('Unknown symmetric algorithm encountered');
      }

      final key = s2k!.produceKey(passphrase, symmetricAlgorithm);
      final cipher = BufferedCipher(engine);
      cipher.init(false, pc.ParametersWithIV(pc.KeyParameter(key), iv));

      var clearTextWithHash = Uint8List(keyData.length);
      final length = cipher.processBytes(keyData, 0, keyData.length, clearTextWithHash, 0);
      cipher.doFinal(clearTextWithHash, length);

      final hashLen = 20;
      clearText = clearTextWithHash.sublist(0, clearTextWithHash.length - hashLen);
      final hashText = clearTextWithHash.sublist(clearTextWithHash.length - hashLen);
      s2k!.digest.reset();
      final hash = s2k!.digest.process(clearText);
      if (!hash.equals(hashText)) {
        throw Exception('Incorrect key passphrase');
      }
    } else {
      clearText = keyData;
    }

    final KeyParams keyParams;
    switch (publicKey.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        keyParams = RSASecretParams.fromPacketData(clearText);
        break;
      case KeyAlgorithm.elgamal:
        keyParams = ElGamalSecretParams.fromPacketData(clearText);
        break;
      case KeyAlgorithm.dsa:
        keyParams = DSASecretParams.fromPacketData(clearText);
        break;
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
        keyParams = ECSecretParams.fromPacketData(clearText);
        break;
      default:
        throw UnsupportedError('Unknown PGP public key algorithm encountered');
    }
    return keyParams;
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

  @override
  KeyAlgorithm get algorithm => publicKey.algorithm;

  @override
  DateTime get creationTime => publicKey.creationTime;

  @override
  int get expirationDays => publicKey.expirationDays;

  @override
  String get fingerprint => publicKey.fingerprint;

  @override
  KeyID get keyID => publicKey.keyID;

  @override
  int get version => publicKey.version;
}
