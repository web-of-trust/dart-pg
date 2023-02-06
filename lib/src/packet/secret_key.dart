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

  Uint8List _keyData;

  S2kUsage _s2kUsage;

  SymmetricAlgorithm _symmetricAlgorithm;

  S2K? _s2k;

  Uint8List? _iv;

  KeyParams? _secretParams;

  SecretKeyPacket(
    this.publicKey,
    Uint8List keyData, {
    S2kUsage s2kUsage = S2kUsage.sha1,
    SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    Uint8List? iv,
    S2K? s2k,
    KeyParams? secretParams,
    super.tag = PacketTag.secretKey,
  })  : _keyData = keyData,
        _s2kUsage = s2kUsage,
        _symmetricAlgorithm = symmetricAlgorithm,
        _iv = iv,
        _s2k = s2k,
        _secretParams = secretParams;

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

    final Uint8List? iv;
    if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      final blockSize = symmetricAlgorithm.blockSize;
      iv = bytes.sublist(pos, pos + blockSize);
      pos += blockSize;
    } else {
      iv = null;
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
      iv: iv,
      s2k: s2k,
      secretParams: secretParams,
    );
  }

  bool get isEncrypted => _s2kUsage != S2kUsage.none;

  bool get isDecrypted => _secretParams != null;

  bool get isDummy => _s2k != null && _s2k!.type == S2kType.gnu;

  Uint8List get keyData => _keyData;

  S2kUsage get s2kUsage => _s2kUsage;

  SymmetricAlgorithm get symmetricAlgorithm => _symmetricAlgorithm;

  S2K? get s2k => _s2k;

  Uint8List? get iv => _iv;

  KeyParams? get secretParams => _secretParams;

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

  Uint8List encrypt(
    String passphrase, {
    S2kUsage s2kUsage = S2kUsage.sha1,
    SymmetricAlgorithm symmetricAlgorithm = OpenPGP.preferredSymmetricAlgorithm,
    HashAlgorithm hash = HashAlgorithm.sha1,
    S2kType type = S2kType.iterated,
  }) {
    if (_secretParams != null) {
      final random = newSecureRandom();
      _s2kUsage = s2kUsage;
      _symmetricAlgorithm = symmetricAlgorithm;
      _s2k = S2K(random.nextBytes(8), hash: hash, type: type);
      _iv = random.nextBytes(symmetricAlgorithm.blockSize);

      final key = _s2k!.produceKey(passphrase, symmetricAlgorithm);
      final cipher = BufferedCipher(_cipherEngine());
      cipher.init(true, pc.ParametersWithIV(pc.KeyParameter(key), _iv!));

      _s2k!.digest.reset();
      final clearText = _secretParams!.encode();
      final clearTextWithHash = Uint8List.fromList([...clearText, ..._s2k!.digest.process(clearText)]);

      _keyData = Uint8List(clearTextWithHash.length);
      final length = cipher.processBytes(clearTextWithHash, 0, clearTextWithHash.length, _keyData, 0);
      cipher.doFinal(_keyData, length);
    }
    return _keyData;
  }

  KeyParams decrypt(String passphrase) {
    if (!isDecrypted) {
      final Uint8List clearText;
      if (isEncrypted) {
        final key = _s2k!.produceKey(passphrase, _symmetricAlgorithm);
        final cipher = BufferedCipher(_cipherEngine());
        cipher.init(false, pc.ParametersWithIV(pc.KeyParameter(key), _iv!));

        final clearTextWithHash = Uint8List(_keyData.length);
        final length = cipher.processBytes(_keyData, 0, _keyData.length, clearTextWithHash, 0);
        cipher.doFinal(clearTextWithHash, length);

        final hashLen = _s2k!.digest.digestSize;
        clearText = clearTextWithHash.sublist(0, clearTextWithHash.length - hashLen);
        final hashText = clearTextWithHash.sublist(clearTextWithHash.length - hashLen);
        _s2k!.digest.reset();
        final hash = _s2k!.digest.process(clearText);
        if (!hash.equals(hashText)) {
          throw Exception('Incorrect key passphrase');
        }
      } else {
        clearText = _keyData;
      }

      _secretParams = _parseSecretParams(clearText, publicKey.algorithm);
    }
    return _secretParams!;
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [...publicKey.toPacketData(), _s2kUsage.value];
    if (_s2kUsage != S2kUsage.none && _s2k != null) {
      bytes.addAll([_symmetricAlgorithm.value, ..._s2k!.encode()]);
      if (_iv != null) {
        bytes.addAll([..._iv!]);
      }
    }
    bytes.addAll([..._keyData]);
    return Uint8List.fromList(bytes);
  }

  pc.BlockCipher _cipherEngine() {
    final pc.BlockCipher engine;
    switch (_symmetricAlgorithm) {
      case SymmetricAlgorithm.aes128:
      case SymmetricAlgorithm.aes192:
      case SymmetricAlgorithm.aes256:
        engine = pc.BlockCipher('AES/CFB-${_symmetricAlgorithm.keySize}');
        break;
      case SymmetricAlgorithm.blowfish:
        engine = CFBBlockCipher(BlowfishEngine(), _symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.camellia128:
      case SymmetricAlgorithm.camellia192:
      case SymmetricAlgorithm.camellia256:
        engine = CFBBlockCipher(CamelliaEngine(), _symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.cast5:
        engine = CFBBlockCipher(CAST5Engine(), _symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.idea:
        engine = CFBBlockCipher(IDEAEngine(), _symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.tripledes:
        engine = CFBBlockCipher(TripleDESEngine(), _symmetricAlgorithm.blockSize);
        break;
      case SymmetricAlgorithm.twofish:
        engine = CFBBlockCipher(TwofishEngine(), _symmetricAlgorithm.blockSize);
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
