// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';
import 'key/key_id.dart';
import 'key/key_params.dart';
import 'key/s2k.dart';
import 'contained_packet.dart';
import 'key_packet.dart';

/// SecretKey represents a possibly encrypted private key.
/// See RFC 4880, section 5.5.3.
class SecretKeyPacket extends ContainedPacket implements KeyPacket {
  final PublicKeyPacket _publicKey;

  final Uint8List keyData;

  final S2kUsage s2kUsage;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2K? s2k;

  final Uint8List? iv;

  final KeyParams? secretParams;

  SecretKeyPacket(
    this._publicKey,
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
        pos += s2k.length;
        break;
      default:
        symmetricAlgorithm = SymmetricAlgorithm.plaintext;
        s2k = null;
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

  PublicKeyPacket get publicKey => _publicKey;

  bool get isEncrypted => s2kUsage != S2kUsage.none;

  bool get isDecrypted => secretParams != null;

  bool get isDummy => s2k != null && s2k!.type == S2kType.gnu;

  @override
  KeyAlgorithm get algorithm => _publicKey.algorithm;

  @override
  DateTime get creationTime => _publicKey.creationTime;

  @override
  KeyParams get publicParams => _publicKey.publicParams;

  @override
  int get expirationDays => _publicKey.expirationDays;

  @override
  String get fingerprint => _publicKey.fingerprint;

  @override
  KeyID get keyID => _publicKey.keyID;

  @override
  int get version => _publicKey.version;

  @override
  int get keyStrength => _publicKey.keyStrength;

  SecretKeyPacket encrypt(
    final String passphrase, {
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    final HashAlgorithm hash = HashAlgorithm.sha1,
    final S2kType type = S2kType.iterated,
  }) {
    if (secretParams != null) {
      if (passphrase.isEmpty) {
        throw ArgumentError('passphrase are required for key encryption');
      }
      assert(s2kUsage != S2kUsage.none);
      assert(symmetricAlgorithm != SymmetricAlgorithm.plaintext);

      final random = Helper.secureRandom();
      final s2k = S2K(random.nextBytes(8), hash: hash, type: type);
      final iv = random.nextBytes(symmetricAlgorithm.blockSize);

      final key = s2k.produceKey(passphrase, symmetricAlgorithm);
      final cipher = BufferedCipher(_cipherEngine(symmetricAlgorithm))
        ..init(true, ParametersWithIV(KeyParameter(key), iv));

      final clearText = secretParams!.encode();
      final clearTextWithHash = Uint8List.fromList([...clearText, ...Helper.hashDigest(clearText, s2k.hash)]);
      final cipherText = cipher.process(clearTextWithHash);

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

  SecretKeyPacket decrypt(final String passphrase) {
    if (secretParams == null) {
      final Uint8List clearText;
      if (isEncrypted) {
        final key = s2k?.produceKey(passphrase, symmetricAlgorithm) ?? Uint8List((symmetricAlgorithm.keySize + 7) >> 3);
        final cipher = BufferedCipher(_cipherEngine(symmetricAlgorithm))
          ..init(
            false,
            ParametersWithIV(
              KeyParameter(key),
              iv ?? Uint8List(symmetricAlgorithm.blockSize),
            ),
          );

        final clearTextWithHash = cipher.process(keyData);
        final hash = s2k?.hash ?? HashAlgorithm.sha1;
        clearText = clearTextWithHash.sublist(0, clearTextWithHash.length - hash.digestSize);
        final hashText = clearTextWithHash.sublist(clearTextWithHash.length - hash.digestSize);
        final hashed = Helper.hashDigest(clearText, hash);
        if (!hashed.equals(hashText)) {
          throw ArgumentError('Incorrect key passphrase');
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

  SecretKeyPacket clearSecretParams() {
    if (secretParams == null) {
      return this;
    } else {
      return SecretKeyPacket(
        publicKey,
        keyData,
        s2kUsage: s2kUsage,
        symmetricAlgorithm: symmetricAlgorithm,
        s2k: s2k,
        iv: iv,
      );
    }
  }

  @override
  Uint8List writeForHash() {
    return publicKey.writeForHash();
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes;
    if (s2kUsage != S2kUsage.none && s2k != null) {
      bytes = [
        ...publicKey.toPacketData(),
        s2kUsage.value,
        symmetricAlgorithm.value,
        ...s2k!.encode(),
        ...iv ?? [],
        ...keyData,
      ];
    } else {
      bytes = [...publicKey.toPacketData(), s2kUsage.value, ...keyData];
    }

    return Uint8List.fromList(bytes);
  }

  static BlockCipher _cipherEngine(final SymmetricAlgorithm symmetricAlgorithm) {
    final BlockCipher engine;
    switch (symmetricAlgorithm) {
      case SymmetricAlgorithm.aes128:
      case SymmetricAlgorithm.aes192:
      case SymmetricAlgorithm.aes256:
        engine = BlockCipher('AES/CFB-${symmetricAlgorithm.blockSize * 8}');
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

  static KeyParams _parseSecretParams(final Uint8List packetData, final KeyAlgorithm algorithm) {
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
