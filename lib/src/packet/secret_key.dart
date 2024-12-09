/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../common/argon2_s2k.dart';
import '../common/config.dart';
import '../common/generic_s2k.dart';
import '../common/helpers.dart';
import '../cryptor/symmetric/buffered_cipher.dart';
import '../enum/rsa_key_size.dart';
import '../enum/aead_algorithm.dart';
import '../enum/ecc.dart';
import '../enum/eddsa_curve.dart';
import '../enum/montgomery_curve.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_version.dart';
import '../enum/key_algorithm.dart';
import '../enum/s2k_type.dart';
import '../enum/s2k_usage.dart';
import '../enum/symmetric_algorithm.dart';
import '../type/s2k.dart';
import '../type/secret_key_material.dart';
import '../type/secret_key_packet.dart';
import '../type/subkey_packet.dart';
import 'key/public_material.dart';
import 'key/secret_material.dart';
import 'base_packet.dart';

/// Implementation of the Secret Key (SECKEY) Packet - Type 5
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SecretKeyPacket extends BasePacket implements SecretKeyPacketInterface {
  @override
  final PublicKeyPacket publicKey;

  final Uint8List keyData;

  final S2kUsage s2kUsage;

  final SymmetricAlgorithm? symmetric;

  final AeadAlgorithm? aead;

  final S2kInterface? s2k;

  final Uint8List? iv;

  @override
  final SecretKeyMaterialInterface? secretKeyMaterial;

  SecretKeyPacket(
    this.publicKey,
    this.keyData, {
    this.s2kUsage = S2kUsage.none,
    this.symmetric,
    this.aead,
    this.s2k,
    this.iv,
    this.secretKeyMaterial,
  }) : super(PacketType.secretKey);

  factory SecretKeyPacket.fromBytes(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromBytes(bytes);
    final keyRecord = parseBytes(bytes, publicKey);
    return SecretKeyPacket(
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

  /// Generate secret key packet
  factory SecretKeyPacket.generate(
    final KeyAlgorithm algorithm, {
    final RSAKeySize rsaKeySize = RSAKeySize.normal,
    final Ecc curve = Ecc.secp521r1,
    final DateTime? time,
  }) {
    final keyMaterial = generateKeyMaterial(
      algorithm,
      rsaKeySize: rsaKeySize,
      curve: curve,
    );

    return SecretKeyPacket(
      PublicKeyPacket(
        algorithm.keyVersion,
        time ?? DateTime.now(),
        keyMaterial.publicMaterial,
        keyAlgorithm: algorithm,
      ),
      keyMaterial.toBytes,
      secretKeyMaterial: keyMaterial,
    );
  }

  static SecretKeyMaterialInterface generateKeyMaterial(
    final KeyAlgorithm algorithm, {
    final RSAKeySize rsaKeySize = RSAKeySize.normal,
    final Ecc curve = Ecc.secp521r1,
  }) {
    return switch (algorithm) {
      KeyAlgorithm.rsaEncryptSign ||
      KeyAlgorithm.rsaSign ||
      KeyAlgorithm.rsaEncrypt =>
        RSASecretMaterial.generate(rsaKeySize),
      KeyAlgorithm.ecdsa => ECDSASecretMaterial.generate(curve),
      KeyAlgorithm.ecdh => ECDHSecretMaterial.generate(curve),
      KeyAlgorithm.eddsaLegacy => EdDSALegacySecretMaterial.generate(),
      KeyAlgorithm.x25519 => MontgomerySecretMaterial.generate(MontgomeryCurve.x25519),
      KeyAlgorithm.x448 => MontgomerySecretMaterial.generate(MontgomeryCurve.x448),
      KeyAlgorithm.ed25519 => EdDSASecretMaterial.generate(EdDSACurve.ed25519),
      KeyAlgorithm.ed448 => EdDSASecretMaterial.generate(EdDSACurve.ed448),
      _ => throw UnsupportedError("Key algorithm ${algorithm.name} is unsupported."),
    };
  }

  static ({
    Uint8List keyData,
    S2kUsage s2kUsage,
    SymmetricAlgorithm symmetric,
    AeadAlgorithm? aead,
    S2kInterface? s2k,
    Uint8List? iv,
    SecretKeyMaterialInterface? keyMaterial,
  }) parseBytes(
    final Uint8List bytes,
    final PublicKeyPacket publicKey,
  ) {
    final isV6 = publicKey.keyVersion == KeyVersion.v6.value;

    var pos = publicKey.data.length;
    final s2kUsage = S2kUsage.values.firstWhere(
      (usage) => usage.value == bytes[pos],
    );
    pos++;

    // Only for a version 6 packet where the secret key material encrypted
    if (isV6 && s2kUsage != S2kUsage.none) {
      pos++;
    }

    final S2kInterface? s2k;
    final AeadAlgorithm? aead;
    final SymmetricAlgorithm symmetric;
    switch (s2kUsage) {
      case S2kUsage.malleableCfb:
      case S2kUsage.cfb:
      case S2kUsage.aeadProtect:
        symmetric = SymmetricAlgorithm.values.firstWhere(
          (usage) => usage.value == bytes[pos],
        );
        pos++;

        // If s2k usage octet was 253, a one-octet AEAD algorithm.
        if (s2kUsage == S2kUsage.aeadProtect) {
          aead = AeadAlgorithm.values.firstWhere(
            (usage) => usage.value == bytes[pos],
          );
          pos++;
        } else {
          aead = null;
        }

        // Only for a version 6 packet, and if string-to-key usage
        // octet was 253 or 254, an one-octet count of the following field.
        if (isV6 && (s2kUsage == S2kUsage.aeadProtect || s2kUsage == S2kUsage.cfb)) {
          pos++;
        }

        final s2kType = S2kType.values.firstWhere(
          (usage) => usage.value == bytes[pos],
        );

        if (s2kType == S2kType.argon2) {
          s2k = Argon2S2k.fromBytes(bytes.sublist(pos));
        } else {
          s2k = GenericS2k.fromBytes(bytes.sublist(pos));
        }
        pos += s2k.length;
        break;
      default:
        symmetric = SymmetricAlgorithm.plaintext;
        s2k = null;
        aead = null;
    }

    Uint8List? iv;
    if (aead != null) {
      iv = bytes.sublist(pos, pos + aead.ivLength);
      pos += aead.ivLength;
    } else if (!(s2k != null && s2k.type == S2kType.gnu) && s2kUsage != S2kUsage.none) {
      iv = bytes.sublist(pos, pos + symmetric.blockSize);
      pos += symmetric.blockSize;
    }

    SecretKeyMaterialInterface? keyMaterial;
    var keyData = bytes.sublist(pos);
    if (s2kUsage == S2kUsage.none) {
      if (!isV6) {
        final checksum = keyData.sublist(keyData.length - 2);
        keyData = keyData.sublist(0, keyData.length - 2);
        if (!checksum.equals(_computeChecksum(keyData))) {
          throw StateError('Key checksum mismatch!');
        }
      }
      keyMaterial = _readKeyMaterial(
        keyData,
        publicKey,
      );
    }

    return (
      keyData: keyData,
      s2kUsage: s2kUsage,
      symmetric: symmetric,
      aead: aead,
      s2k: s2k,
      iv: iv,
      keyMaterial: keyMaterial,
    );
  }

  @override
  encrypt(
    final String passphrase,
    final SymmetricAlgorithm symmetric, [
    final AeadAlgorithm? aead,
  ]) {
    if (secretKeyMaterial != null) {
      final record = encryptKeyMaterial(passphrase, symmetric, aead);
      return SecretKeyPacket(
        publicKey,
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
  decrypt(final String passphrase) {
    if (secretKeyMaterial == null) {
      return SecretKeyPacket(
        publicKey,
        keyData,
        s2kUsage: s2kUsage,
        symmetric: symmetric,
        aead: aead,
        s2k: s2k,
        iv: iv,
        secretKeyMaterial: decryptKeyData(passphrase),
      );
    } else {
      return this;
    }
  }

  ({
    Uint8List cipherText,
    Uint8List iv,
    S2kInterface s2k,
  }) encryptKeyMaterial(
    final String passphrase,
    final SymmetricAlgorithm symmetric, [
    final AeadAlgorithm? aead,
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase are required for key encryption');
    }
    Helper.assertSymmetric(symmetric);
    final aeadProtect = aead != null;
    final isV6 = keyVersion == KeyVersion.v6.value;
    if (aeadProtect && !isV6) {
      throw ArgumentError(
        'Using AEAD with version $keyVersion of the key packet is not allowed.',
      );
    }
    final s2k = aeadProtect || isV6
        ? Helper.stringToKey(
            S2kType.argon2,
          )
        : Helper.stringToKey(
            S2kType.iterated,
          );
    final iv = aeadProtect
        ? Helper.randomBytes(
            aead.ivLength,
          )
        : Helper.randomBytes(
            symmetric.blockSize,
          );
    final kek = _produceEncryptionKey(
      passphrase,
      symmetric,
      type,
      s2k: s2k,
      aead: aead,
    );
    final clearText = secretKeyMaterial!.toBytes;
    final Uint8List cipherText;
    if (aeadProtect) {
      final cipher = aead.cipherEngine(kek, symmetric);
      cipherText = cipher.encrypt(
          clearText,
          iv,
          Uint8List.fromList([
            type.value | 0xc0,
            ...publicKey.data,
          ]));
    } else {
      final cipher = BufferedCipher(symmetric.cfbCipherEngine)
        ..init(
          true,
          ParametersWithIV(KeyParameter(kek), iv),
        );

      cipherText = cipher.process(Uint8List.fromList([
        ...clearText,
        ...Helper.hashDigest(clearText, HashAlgorithm.sha1),
      ]));
    }
    return (
      cipherText: cipherText,
      iv: iv,
      s2k: s2k,
    );
  }

  SecretKeyMaterialInterface decryptKeyData(final String passphrase) {
    final Uint8List clearText;
    if (isEncrypted) {
      final kek = _produceEncryptionKey(
        passphrase,
        symmetric!,
        type,
        s2k: s2k,
        aead: aead,
      );
      if (aead != null) {
        final cipher = aead!.cipherEngine(kek, symmetric!);
        clearText = cipher.decrypt(
            keyData,
            iv!,
            Uint8List.fromList([
              type.value | 0xc0,
              ...publicKey.data,
            ]));
      } else {
        final cipher = BufferedCipher(symmetric!.cfbCipherEngine)
          ..init(
            false,
            ParametersWithIV(
              KeyParameter(kek),
              iv ?? Uint8List(symmetric!.blockSize),
            ),
          );

        final clearTextWithHash = cipher.process(keyData);
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
      }
    } else {
      clearText = keyData;
    }
    return _readKeyMaterial(clearText, publicKey);
  }

  @override
  get data {
    final isV6 = publicKey.keyVersion == KeyVersion.v6.value;
    if (isEncrypted) {
      final optBytes = Uint8List.fromList([
        symmetric!.value,
        ...aead != null ? [aead!.value] : [],
        ...isV6 ? [s2k!.length] : [],
        ...s2k!.toBytes,
        ...iv ?? [],
      ]);
      return Uint8List.fromList([
        ...publicKey.data,
        s2kUsage.value,
        ...isV6 ? [optBytes.length] : [],
        ...optBytes,
        ...keyData,
      ]);
    } else {
      return Uint8List.fromList([
        ...publicKey.data,
        S2kUsage.none.value,
        ...keyData,
        ...isV6 ? [] : _computeChecksum(keyData),
      ]);
    }
  }

  @override
  get signBytes => publicKey.signBytes;

  @override
  get creationTime => publicKey.creationTime;

  @override
  get fingerprint => publicKey.fingerprint;

  @override
  get isDecrypted => secretKeyMaterial != null;

  @override
  get isEncrypted => s2kUsage != S2kUsage.none && symmetric != null;

  @override
  get isEncryptionKey => publicKey.isEncryptionKey;

  @override
  get isSigningKey => publicKey.isSigningKey;

  @override
  get isSubkey => this is SubkeyPacketInterface;
  
  @override
  bool get isV6Key => publicKey.isV6Key;

  @override
  get keyAlgorithm => publicKey.keyAlgorithm;

  @override
  get keyID => publicKey.keyID;

  @override
  get keyMaterial => publicKey.keyMaterial;

  @override
  get keyStrength => publicKey.keyStrength;

  @override
  get keyVersion => publicKey.keyVersion;

  @override
  get aeadProtected => aead != null;

  @override
  get preferredHash {
    if ((keyMaterial is ECPublicMaterial)) {
      final curve = Ecc.values.firstWhere(
        (info) => info.asn1Oid == (keyMaterial as ECPublicMaterial).oid,
        orElse: () => Ecc.secp521r1,
      );
      return curve.hashAlgorithm;
    } else if (keyMaterial is EdDSAPublicMaterial) {
      return (keyMaterial as EdDSAPublicMaterial).curve.hashAlgorithm;
    } else {
      return Config.preferredHash;
    }
  }

  static Uint8List _produceEncryptionKey(
    final String passphrase,
    final SymmetricAlgorithm symmetric,
    final PacketType type, {
    final S2kInterface? s2k,
    final AeadAlgorithm? aead,
  }) {
    final derivedKey = s2k != null
        ? s2k.produceKey(
            passphrase,
            symmetric.keySizeInByte,
          )
        : Uint8List(symmetric.keySizeInByte);
    if (aead != null) {
      return Helper.hkdf(
        derivedKey,
        symmetric.keySizeInByte,
        info: Uint8List.fromList([
          type.value | 0xc0,
          KeyVersion.v6.value,
          symmetric.value,
          aead.value,
        ]),
      );
    }
    return derivedKey;
  }

  static SecretKeyMaterialInterface _readKeyMaterial(
    final Uint8List keyData,
    final PublicKeyPacket publicKey,
  ) {
    final keyMaterial = switch (publicKey.keyAlgorithm) {
      KeyAlgorithm.rsaEncryptSign || KeyAlgorithm.rsaSign || KeyAlgorithm.rsaEncrypt => RSASecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as RSAPublicMaterial,
        ),
      KeyAlgorithm.dsa => DSASecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as DSAPublicMaterial,
        ),
      KeyAlgorithm.elgamal => ElGamalSecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as ElGamalPublicMaterial,
        ),
      KeyAlgorithm.ecdsa => ECDSASecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as ECDSAPublicMaterial,
        ),
      KeyAlgorithm.ecdh => ECDHSecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as ECDHPublicMaterial,
        ),
      KeyAlgorithm.eddsaLegacy => EdDSALegacySecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as EdDSALegacyPublicMaterial,
        ),
      KeyAlgorithm.x25519 || KeyAlgorithm.x448 => MontgomerySecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as MontgomeryPublicMaterial,
        ),
      KeyAlgorithm.ed25519 || KeyAlgorithm.ed448 => EdDSASecretMaterial.fromBytes(
          keyData,
          publicKey.keyMaterial as EdDSAPublicMaterial,
        ),
      _ => throw UnsupportedError(
          'Public key algorithm ${publicKey.keyAlgorithm.name} is unsupported.',
        ),
    };

    if (!keyMaterial.isValid) {
      throw StateError('Key material is not consistent.');
    }

    return keyMaterial;
  }

  static Uint8List _computeChecksum(Uint8List keyData) {
    var sum = 0;
    for (var i = 0; i < keyData.length; i++) {
      sum = (sum + keyData[i]) & 0xffff;
    }
    return sum.pack16();
  }
}
