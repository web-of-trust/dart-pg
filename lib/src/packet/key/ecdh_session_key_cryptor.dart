/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pinenacl/api.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';
import 'package:pointycastle/export.dart';

import '../../common/helpers.dart';
import '../../enum/ecc.dart';
import '../../enum/hash_algorithm.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/symmetric_algorithm.dart';
import '../../type/secret_key_material.dart';
import 'ecdh_public_material.dart';
import 'ecdh_secret_material.dart';
import 'key_wrapper.dart';
import 'session_key_cryptor.dart';

/// ECDH session key cryptor class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ECDHSessionKeyCryptor extends SessionKeyCryptor {
  /// 20 octets representing the UTF-8 encoding of the string 'Anonymous Sender    '
  static const _anonymousSender = [
    0x41, 0x6e, 0x6f, 0x6e, // 0 - 3
    0x79, 0x6d, 0x6f, 0x75,
    0x73, 0x20, 0x53, 0x65,
    0x6e, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20
  ];

  /// MPI containing the ephemeral key used to establish the shared secret
  final BigInt ephemeralKey;

  /// ECDH wrapped key
  final Uint8List wrappedKey;

  /// OpenPGP public key fingerprint
  Uint8List fingerprint = Uint8List(0);

  ECDHSessionKeyCryptor(this.ephemeralKey, this.wrappedKey);

  factory ECDHSessionKeyCryptor.fromBytes(
    final Uint8List bytes,
  ) {
    final ephemeralKey = Helper.readMPI(bytes);

    final pos = ephemeralKey.byteLength + 2;
    final length = bytes[pos];

    return ECDHSessionKeyCryptor(
      ephemeralKey,
      bytes.sublist(pos + 1, pos + length + 1),
    );
  }

  factory ECDHSessionKeyCryptor.encryptSessionKey(
    final Uint8List sessionKey,
    final ECDHPublicMaterial key,
    final Uint8List fingerprint,
  ) {
    final BigInt ephemeralKey;
    final Uint8List sharedKey;

    /// Generate the ephemeral key
    switch (key.curve) {
      case Ecc.curve25519:
        final privateKey = nacl.PrivateKey.fromSeed(
          Helper.randomBytes(TweetNaCl.seedSize),
        );
        ephemeralKey = Uint8List.fromList([
          0x40,
          ...privateKey.publicKey.asTypedList,
        ]).toUnsignedBigInt();
        sharedKey = TweetNaCl.crypto_scalarmult(
          Uint8List(TweetNaCl.sharedKeyLength),
          privateKey.asTypedList,
          key.q.toUnsignedBytes().sublist(1),
        );
        break;
      case Ecc.ed25519:
        throw UnsupportedError(
          'Curve ${key.curve.name} is unsupported for ephemeral key generation.',
        );
      default:
        final parameters = ECDomainParameters(
          key.curve.name.toLowerCase(),
        );
        final keyGen = KeyGenerator('EC')
          ..init(
            ParametersWithRandom(
              ECKeyGeneratorParameters(parameters),
              Helper.secureRandom,
            ),
          );
        final keyPair = keyGen.generateKeyPair();
        final agreement = ECDHBasicAgreement()
          ..init(
            keyPair.privateKey as ECPrivateKey,
          );
        sharedKey = agreement
            .calculateAgreement(ECPublicKey(
              parameters.curve.decodePoint(key.q.toUnsignedBytes()),
              parameters,
            ))
            .toUnsignedBytes();
        final publicKey = keyPair.publicKey as ECPublicKey;
        ephemeralKey = publicKey.Q!.getEncoded(false).toUnsignedBigInt();
    }
    final keyWrapper = _selectKeyWrapper(key.kdfSymmetric);
    return ECDHSessionKeyCryptor(
      ephemeralKey,
      keyWrapper.wrap(
        _kdf(
          key.kdfHash,
          sharedKey,
          _ecdhParam(key, fingerprint),
          (key.kdfSymmetric.keySize + 7) >> 3,
        ),
        _pkcs5Encode(sessionKey),
      ),
    );
  }

  @override
  Uint8List decrypt(final SecretKeyMaterialInterface key) {
    if (key is ECDHSecretMaterial) {
      final Uint8List sharedKey;
      switch (key.publicMaterial.curve) {
        case Ecc.curve25519:
          sharedKey = TweetNaCl.crypto_scalarmult(
            Uint8List(TweetNaCl.sharedKeyLength),
            Uint8List.fromList(
              key.d.toUnsignedBytes().reversed.toList(),
            ),
            ephemeralKey.toUnsignedBytes().sublist(1),
          );
          break;
        case Ecc.ed25519:
          throw UnsupportedError(
            'Curve ${key.publicMaterial.curve.name} is unsupported for key agreement calculation.',
          );
        default:
          final parameters = ECDomainParameters(
            key.publicMaterial.curve.name.toLowerCase(),
          );
          final privateKey = ECPrivateKey(key.d, parameters);
          final agreement = ECDHBasicAgreement()..init(privateKey);
          sharedKey = agreement
              .calculateAgreement(
                ECPublicKey(
                  parameters.curve.decodePoint(ephemeralKey.toUnsignedBytes()),
                  parameters,
                ),
              )
              .toUnsignedBytes();
      }
      final keyWrapper = _selectKeyWrapper(key.publicMaterial.kdfSymmetric);
      return _pkcs5Decode(
        keyWrapper.unwrap(
          _kdf(
            key.publicMaterial.kdfHash,
            sharedKey,
            _ecdhParam(key.publicMaterial, fingerprint),
            (key.publicMaterial.kdfSymmetric.keySize + 7) >> 3,
          ),
          wrappedKey,
        ),
      );
    } else {
      throw ArgumentError('Secret key material is not ECDH key.');
    }
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...ephemeralKey.bitLength.pack16(),
        ...ephemeralKey.toUnsignedBytes(),
        wrappedKey.length,
        ...wrappedKey,
      ]);

  /// Key Derivation Function (RFC 6637)
  static Uint8List _kdf(
    final HashAlgorithm hash,
    final Uint8List sharedKey,
    final Uint8List param,
    final int keySize,
  ) =>
      Helper.hashDigest(
        Uint8List.fromList([
          0,
          0,
          0,
          1,
          ...sharedKey,
          ...param,
        ]),
        hash,
      ).sublist(0, keySize);

  /// Build Param for ECDH algorithm (RFC 6637)
  static Uint8List _ecdhParam(
    final ECDHPublicMaterial publicMaterial,
    final Uint8List fingerprint,
  ) =>
      Uint8List.fromList([
        ...publicMaterial.oid.encode().sublist(1),
        KeyAlgorithm.ecdh.value,
        0x3,
        publicMaterial.reserved,
        publicMaterial.kdfHash.value,
        publicMaterial.kdfSymmetric.value,
        ..._anonymousSender,
        ...fingerprint,
      ]);

  /// Add pkcs5 padding to a message
  static Uint8List _pkcs5Encode(final Uint8List message) {
    final c = 8 - (message.length % 8);
    return Uint8List.fromList(
      List.filled(message.length + c, c),
    )..setAll(0, message);
  }

  /// Remove pkcs5 padding from a message
  static Uint8List _pkcs5Decode(final Uint8List message) {
    final length = message.length;
    if (length > 0) {
      final c = message[length - 1];
      if (c >= 1) {
        final provided = message.sublist(length - c);
        final computed = Uint8List.fromList(List.filled(c, c));
        if (provided.equals(computed)) {
          return message.sublist(0, length - c);
        }
      }
    }
    return Uint8List(0);
  }

  static KeyWrapper _selectKeyWrapper(final SymmetricAlgorithm symmetric) {
    switch (symmetric) {
      case SymmetricAlgorithm.camellia128:
      case SymmetricAlgorithm.camellia192:
      case SymmetricAlgorithm.camellia256:
        return CamelliaKeyWrapper((symmetric.keySize + 7) >> 3);
      default:
        return AesKeyWrapper((symmetric.keySize + 7) >> 3);
    }
  }
}
