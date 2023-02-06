// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/key/key_id.dart';
import 'package:dart_pg/src/openpgp.dart';
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

  final Uint8List keyData;

  final S2kUsage s2kUsage;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2K? s2k;

  final Uint8List? iv;

  final KeyParams? secretParams;

  SecretKeyPacket(
    this.publicKey,
    this.keyData, {
    this.s2kUsage = S2kUsage.sha1,
    this.symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    this.s2k,
    this.iv,
    this.secretParams,
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
        symmetricAlgorithm = SymmetricAlgorithm.plaintext;
        s2k = null;
    }
    if (s2k != null) {
      pos += s2k.encode().length;
    }

    Uint8List? iv;
    if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      final blockSize = symmetricAlgorithm.blockSize;
      iv = bytes.sublist(pos, pos + blockSize);
      pos += blockSize;
    }

    KeyParams? secretParams;
    if (s2kUsage == S2kUsage.none) {
      secretParams = _parseSecretParams(bytes.sublist(pos), publicKey.algorithm);
    }

    return SecretKeyPacket(
      publicKey,
      bytes.sublist(pos),
      s2kUsage: s2kUsage,
      symmetricAlgorithm: symmetricAlgorithm,
      s2k: s2k,
      iv: iv,
      secretParams: secretParams,
    );
  }

  bool get isEncrypted => s2kUsage != S2kUsage.none;

  bool get isDecrypted => secretParams != null;

  bool get isDummy => s2k != null && s2k!.type == S2kType.gnu;

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

  SecretKeyPacket encrypt(
    String passphrase, {
    S2kUsage s2kUsage = S2kUsage.sha1,
    SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    HashAlgorithm hash = HashAlgorithm.sha1,
    S2kType type = S2kType.iterated,
  }) {
    assert(s2kUsage != S2kUsage.none);
    assert(symmetricAlgorithm != SymmetricAlgorithm.plaintext);

    if (secretParams != null) {
      final random = newSecureRandom();
      final s2k = S2K(random.nextBytes(8), hash: hash, type: type);
      final iv = random.nextBytes(symmetricAlgorithm.blockSize);

      final key = s2k.produceKey(passphrase, symmetricAlgorithm);
      final cipher = BufferedCipher(_cipherEngine(symmetricAlgorithm));
      cipher.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));

      s2k.digest.reset();
      final clearText = secretParams!.encode();
      final clearTextWithHash = Uint8List.fromList([...clearText, ...s2k.digest.process(clearText)]);

      final cipherText = Uint8List(clearTextWithHash.length);
      final length = cipher.processBytes(clearTextWithHash, 0, clearTextWithHash.length, cipherText, 0);
      cipher.doFinal(cipherText, length);

      return SecretKeyPacket(
        publicKey,
        cipherText,
        s2kUsage: s2kUsage,
        symmetricAlgorithm: symmetricAlgorithm,
        s2k: s2k,
        iv: iv,
        secretParams: secretParams,
      );
    } else {
      return this;
    }
  }

  SecretKeyPacket decrypt(String passphrase) {
    if (secretParams == null) {
      final Uint8List clearText;
      if (isEncrypted) {
        final key = s2k!.produceKey(passphrase, symmetricAlgorithm);
        final cipher = BufferedCipher(_cipherEngine(symmetricAlgorithm));
        cipher.init(false, pc.ParametersWithIV(pc.KeyParameter(key), iv!));

        final clearTextWithHash = Uint8List(keyData.length);
        final length = cipher.processBytes(keyData, 0, keyData.length, clearTextWithHash, 0);
        cipher.doFinal(clearTextWithHash, length);

        final hashLen = s2k!.digest.digestSize;
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

      return SecretKeyPacket(
        publicKey,
        keyData,
        s2kUsage: s2kUsage,
        symmetricAlgorithm: symmetricAlgorithm,
        s2k: s2k,
        iv: iv,
        secretParams: _parseSecretParams(clearText, publicKey.algorithm),
      );
    } else {
      return this;
    }
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [...publicKey.toPacketData(), s2kUsage.value];
    if (s2kUsage != S2kUsage.none && s2k != null) {
      bytes.addAll([symmetricAlgorithm.value, ...s2k!.encode()]);
      if (iv != null) {
        bytes.addAll([...iv!]);
      }
    }
    bytes.addAll([...keyData]);
    return Uint8List.fromList(bytes);
  }

  static pc.BlockCipher _cipherEngine(SymmetricAlgorithm symmetricAlgorithm) {
    final pc.BlockCipher engine;
    switch (symmetricAlgorithm) {
      case SymmetricAlgorithm.aes128:
      case SymmetricAlgorithm.aes192:
      case SymmetricAlgorithm.aes256:
        engine = pc.BlockCipher('AES/CFB-${symmetricAlgorithm.blockSize * 8}');
        break;
      case SymmetricAlgorithm.blowfish:
        engine = CFBBlockCipher(BlowfishEngine(), symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.camellia128:
      case SymmetricAlgorithm.camellia192:
      case SymmetricAlgorithm.camellia256:
        engine = CFBBlockCipher(CamelliaEngine(), symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.cast5:
        engine = CFBBlockCipher(CAST5Engine(), symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.idea:
        engine = CFBBlockCipher(IDEAEngine(), symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.tripledes:
        engine = CFBBlockCipher(TripleDESEngine(), symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.twofish:
        engine = CFBBlockCipher(TwofishEngine(), symmetricAlgorithm.blockSize);
        break;
      default:
        throw UnsupportedError('Unknown symmetric algorithm encountered');
    }
    return engine;
  }

  static KeyParams _parseSecretParams(Uint8List packetData, KeyAlgorithm algorithm) {
    final KeyParams keyParams;
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        keyParams = RSASecretParams.fromPacketData(packetData);
        break;
      case KeyAlgorithm.elgamal:
        keyParams = ElGamalSecretParams.fromPacketData(packetData);
        break;
      case KeyAlgorithm.dsa:
        keyParams = DSASecretParams.fromPacketData(packetData);
        break;
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
        keyParams = ECSecretParams.fromPacketData(packetData);
        break;
      default:
        throw UnsupportedError('Unknown PGP public key algorithm encountered');
    }
    return keyParams;
  }
}
