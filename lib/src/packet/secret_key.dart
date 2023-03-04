// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enum/curve_info.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/s2k_type.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import '../openpgp.dart';
import 'key/key_id.dart';
import 'key/key_pair_params.dart';
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

  final SymmetricAlgorithm symmetric;

  final S2K? s2k;

  final Uint8List? iv;

  final KeyParams? secretParams;

  SecretKeyPacket(
    this._publicKey,
    this.keyData, {
    this.s2kUsage = S2kUsage.sha1,
    this.symmetric = OpenPGP.preferredSymmetric,
    this.s2k,
    this.iv,
    this.secretParams,
  }) : super(PacketTag.secretKey);

  factory SecretKeyPacket.fromPacketData(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromPacketData(bytes);
    final length = publicKey.toPacketData().length;

    var pos = length;
    final s2kUsage = S2kUsage.values.firstWhere((usage) => usage.value == bytes[pos]);
    pos++;

    final S2K? s2k;
    final SymmetricAlgorithm symmetric;
    switch (s2kUsage) {
      case S2kUsage.checksum:
      case S2kUsage.sha1:
        symmetric = SymmetricAlgorithm.values.firstWhere((usage) => usage.value == bytes[pos]);
        pos++;
        s2k = S2K.fromPacketData(bytes.sublist(pos));
        pos += s2k.length;
        break;
      default:
        symmetric = SymmetricAlgorithm.plaintext;
        s2k = null;
    }

    Uint8List? iv;
    if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      final blockSize = symmetric.blockSize;
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
      symmetric: symmetric,
      s2k: s2k,
      iv: iv,
      secretParams: secretParams,
    );
  }

  factory SecretKeyPacket.generate(
    final KeyAlgorithm algorithm, {
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveInfo curve = OpenPGP.preferredCurve,
    final DateTime? date,
  }) {
    final keyPair = KeyPairParams.generate(algorithm, rsaBits: rsaBits, curve: curve);

    return SecretKeyPacket(
      PublicKeyPacket(
        date ?? DateTime.now(),
        keyPair.publicParams,
        algorithm: algorithm,
      ),
      keyPair.secretParams.encode(),
      secretParams: keyPair.secretParams,
    );
  }

  @override
  PublicKeyPacket get publicKey => _publicKey;

  @override
  bool get isEncrypted => s2kUsage != S2kUsage.none;

  @override
  bool get isDecrypted => secretParams != null;

  @override
  bool get isSigningKey {
    return KeyPacket.isSigningAlgorithm(algorithm);
  }

  @override
  bool get isEncryptionKey {
    return KeyPacket.isEncryptionAlgorithm(algorithm);
  }

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

  HashAlgorithm get preferredHash {
    switch (algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        final oid = (publicParams as ECPublicParams).oid;
        final curve = CurveInfo.values.firstWhere(
          (info) => info.identifierString == oid.objectIdentifierAsString,
          orElse: () => OpenPGP.preferredCurve,
        );
        return curve.hashAlgorithm;
      default:
        return OpenPGP.preferredHash;
    }
  }

  SecretKeyPacket encrypt(
    final String passphrase, {
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetric = OpenPGP.preferredSymmetric,
    final HashAlgorithm hash = OpenPGP.preferredHash,
    final S2kType type = S2kType.iterated,
  }) {
    if (secretParams != null) {
      if (passphrase.isEmpty) {
        throw ArgumentError('passphrase are required for key encryption');
      }
      assert(s2kUsage != S2kUsage.none);
      assert(symmetric != SymmetricAlgorithm.plaintext);

      final random = Helper.secureRandom();
      final s2k = S2K(random.nextBytes(8), hash: hash, type: type);
      final iv = random.nextBytes(symmetric.blockSize);

      final key = s2k.produceKey(passphrase, symmetric);
      final cipher = BufferedCipher(symmetric.cipherEngine)..init(true, ParametersWithIV(KeyParameter(key), iv));

      final clearText = secretParams!.encode();
      final clearTextWithHash = Uint8List.fromList([...clearText, ...Helper.hashDigest(clearText, HashAlgorithm.sha1)]);
      final cipherText = cipher.process(clearTextWithHash);

      return SecretKeyPacket(
        publicKey,
        cipherText,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
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
        final key = s2k?.produceKey(passphrase, symmetric) ?? Uint8List((symmetric.keySize + 7) >> 3);
        final cipher = BufferedCipher(symmetric.cipherEngine)
          ..init(
            false,
            ParametersWithIV(
              KeyParameter(key),
              iv ?? Uint8List(symmetric.blockSize),
            ),
          );

        final clearTextWithHash = cipher.process(keyData);
        clearText = clearTextWithHash.sublist(0, clearTextWithHash.length - HashAlgorithm.sha1.digestSize);
        final hashText = clearTextWithHash.sublist(clearTextWithHash.length - HashAlgorithm.sha1.digestSize);
        final hashed = Helper.hashDigest(clearText, HashAlgorithm.sha1);
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
        symmetric: symmetric,
        s2k: s2k,
        iv: iv,
        secretParams: _parseSecretParams(clearText, publicKey.algorithm),
      );
    } else {
      return this;
    }
  }

  @override
  Uint8List writeForSign() {
    return publicKey.writeForSign();
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes;
    if (s2kUsage != S2kUsage.none && s2k != null) {
      bytes = [
        ...publicKey.toPacketData(),
        s2kUsage.value,
        symmetric.value,
        ...s2k!.encode(),
        ...iv ?? [],
        ...keyData,
      ];
    } else {
      bytes = [...publicKey.toPacketData(), s2kUsage.value, ...keyData];
    }

    return Uint8List.fromList(bytes);
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
        throw UnsupportedError('Unsupported public key algorithm encountered');
    }
    return keyParams;
  }
}
