// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../crypto/math/byte_ext.dart';
import '../crypto/math/int_ext.dart';
import '../enum/curve_info.dart';
import '../enum/dh_key_size.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/rsa_key_size.dart';
import '../enum/s2k_type.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import 'key/key_id.dart';
import 'key/key_pair_params.dart';
import 'key/key_params.dart';
import 'key/s2k.dart';
import 'contained_packet.dart';
import 'key_packet.dart';

/// SecretKey represents a possibly encrypted private key.
/// See RFC 4880, section 5.5.3.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
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
    this.symmetric = SymmetricAlgorithm.aes128,
    this.s2k,
    this.iv,
    this.secretParams,
  }) : super(PacketTag.secretKey);

  factory SecretKeyPacket.fromByteData(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromByteData(bytes);

    var pos = publicKey.toByteData().length;
    final s2kUsage = S2kUsage.values.firstWhere(
      (usage) => usage.value == bytes[pos],
    );

    pos++;
    final S2K? s2k;
    final SymmetricAlgorithm symmetric;
    switch (s2kUsage) {
      case S2kUsage.checksum:
      case S2kUsage.sha1:
        symmetric = SymmetricAlgorithm.values.firstWhere(
          (usage) => usage.value == bytes[pos],
        );
        pos++;
        s2k = S2K.fromByteData(bytes.sublist(pos));
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
    var keyData = bytes.sublist(pos);
    if (s2kUsage == S2kUsage.none) {
      final checksum = keyData.sublist(keyData.length - 2);
      keyData = keyData.sublist(0, keyData.length - 2);
      if (!checksum.equals(_computeChecksum(keyData))) {
        throw StateError('Key checksum mismatch!');
      }
      secretParams = _parseSecretParams(
        keyData,
        publicKey.algorithm,
      );
    }

    return SecretKeyPacket(
      publicKey,
      keyData,
      s2kUsage: s2kUsage,
      symmetric: symmetric,
      s2k: s2k,
      iv: iv,
      secretParams: secretParams,
    );
  }

  static Future<SecretKeyPacket> generate(
    final KeyAlgorithm algorithm, {
    final RSAKeySize rsaKeySize = RSAKeySize.s4096,
    final DHKeySize dhKeySize = DHKeySize.l2048n224,
    final CurveInfo curve = CurveInfo.secp521r1,
    final DateTime? date,
  }) async {
    final keyPair = await KeyPairParams.generate(
      algorithm,
      rsaKeySize: rsaKeySize,
      dhKeySize: dhKeySize,
      curve: curve,
    );

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
  String get fingerprint => _publicKey.fingerprint;

  @override
  KeyID get keyID => _publicKey.keyID;

  @override
  int get version => _publicKey.version;

  @override
  int get keyStrength => _publicKey.keyStrength;

  HashAlgorithm get preferredHash {
    final keyParams = publicParams;
    if ((keyParams is ECPublicParams)) {
      final curve = CurveInfo.values.firstWhere(
        (info) => info.asn1Oid == keyParams.oid,
        orElse: () => CurveInfo.secp521r1,
      );
      return curve.hashAlgorithm;
    } else {
      return HashAlgorithm.sha256;
    }
  }

  Future<SecretKeyPacket> encrypt(
    final String passphrase, {
    final S2kUsage s2kUsage = S2kUsage.sha1,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final HashAlgorithm hash = HashAlgorithm.sha1,
    final S2kType type = S2kType.iterated,
  }) async {
    if (secretParams != null) {
      if (passphrase.isEmpty) {
        throw ArgumentError('passphrase are required for key encryption');
      }
      assert(s2kUsage != S2kUsage.none);
      assert(symmetric != SymmetricAlgorithm.plaintext);

      final random = Helper.secureRandom();
      final s2k = S2K(
        random.nextBytes(S2K.saltLength),
        hash: hash,
        type: type,
      );
      final iv = random.nextBytes(symmetric.blockSize);

      final key = await s2k.produceKey(passphrase, symmetric.keySizeInByte);
      final cipher = PaddedBlockCipherImpl(
        Padding('PKCS7'),
        symmetric.cfbCipherEngine,
      );
      cipher.init(
        true,
        PaddedBlockCipherParameters(
          ParametersWithIV(KeyParameter(key), iv),
          null,
        ),
      );

      final clearText = secretParams!.encode();
      final cipherText = cipher.process(
        Helper.pad(
          Uint8List.fromList([
            ...clearText,
            ...Helper.hashDigest(clearText, HashAlgorithm.sha1),
          ]),
          symmetric.blockSize,
        ),
      );

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

  Future<SecretKeyPacket> decrypt(final String passphrase) async {
    if (secretParams == null) {
      final Uint8List clearText;
      if (isEncrypted) {
        final key = await s2k?.produceKey(
              passphrase,
              symmetric.keySizeInByte,
            ) ??
            Uint8List(symmetric.keySizeInByte);
        final cipher = PaddedBlockCipherImpl(
          Padding('PKCS7'),
          symmetric.cfbCipherEngine,
        );
        cipher.init(
          false,
          PaddedBlockCipherParameters(
            ParametersWithIV(
              KeyParameter(key),
              iv ?? Uint8List(symmetric.blockSize),
            ),
            null,
          ),
        );

        final clearTextWithHash = cipher.process(
          Helper.pad(keyData, symmetric.blockSize),
        );
        clearText = clearTextWithHash.sublist(
          0,
          clearTextWithHash.length - HashAlgorithm.sha1.digestSize,
        );
        final hashText = clearTextWithHash.sublist(
          clearTextWithHash.length - HashAlgorithm.sha1.digestSize,
        );
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

  /// Check whether the private and public primary key parameters correspond
  /// Together with verification of binding signatures, this guarantees key integrity
  bool validate() {
    if (secretParams == null) {
      return false;
    }
    final keyParams = secretParams;
    if (keyParams is RSASecretParams) {
      return keyParams.validatePublicParams(publicParams as RSAPublicParams);
    }
    if (keyParams is DSASecretParams) {
      return keyParams.validatePublicParams(publicParams as DSAPublicParams);
    }
    if (keyParams is ElGamalSecretParams) {
      return keyParams.validatePublicParams(publicParams as ElGamalPublicParams);
    }
    if (keyParams is ECSecretParams) {
      return keyParams.validatePublicParams(publicParams as ECPublicParams);
    }
    if (keyParams is EdSecretParams) {
      return keyParams.validatePublicParams(publicParams as EdDSAPublicParams);
    }
    return false;
  }

  @override
  Uint8List writeForSign() {
    return publicKey.writeForSign();
  }

  @override
  Uint8List toByteData() {
    if (s2kUsage != S2kUsage.none && s2k != null) {
      return Uint8List.fromList([
        ...publicKey.toByteData(),
        s2kUsage.value,
        symmetric.value,
        ...s2k!.encode(),
        ...iv ?? [],
        ...keyData,
      ]);
    } else {
      return Uint8List.fromList([
        ...publicKey.toByteData(),
        S2kUsage.none.value,
        ...keyData,
        ..._computeChecksum(keyData),
      ]);
    }
  }

  static KeyParams _parseSecretParams(
    final Uint8List packetData,
    final KeyAlgorithm algorithm,
  ) {
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        return RSASecretParams.fromByteData(packetData);
      case KeyAlgorithm.dsa:
        return DSASecretParams.fromByteData(packetData);
      case KeyAlgorithm.elgamal:
        return ElGamalSecretParams.fromByteData(packetData);
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.ecdh:
        return ECSecretParams.fromByteData(packetData);
      case KeyAlgorithm.eddsa:
        return EdSecretParams.fromByteData(packetData);
      default:
        throw UnsupportedError(
          'Public key algorithm ${algorithm.name} is unsupported.',
        );
    }
  }

  static Uint8List _computeChecksum(Uint8List keyData) {
    var sum = 0;
    for (var i = 0; i < keyData.length; i++) {
      sum = (sum + keyData[i]) & 0xffff;
    }
    return sum.pack16();
  }
}
