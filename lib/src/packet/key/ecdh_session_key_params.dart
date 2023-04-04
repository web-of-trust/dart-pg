// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pinenacl/api.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';
import 'package:pointycastle/export.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/curve_info.dart';
import '../../enum/hash_algorithm.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/symmetric_algorithm.dart';
import '../../helpers.dart';
import 'ec_secret_params.dart';
import 'ecdh_public_params.dart';
import 'key_wrap.dart';
import 'session_key.dart';
import 'session_key_params.dart';

/// Algorithm Specific Params for ECDH encryption
class ECDHSessionKeyParams extends SessionKeyParams {
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

  /// ECDH symmetric key
  final Uint8List wrappedKey;

  ECDHSessionKeyParams(this.ephemeralKey, this.wrappedKey);

  factory ECDHSessionKeyParams.fromByteData(Uint8List bytes) {
    final ephemeralKey = Helper.readMPI(bytes);

    final pos = ephemeralKey.byteLength + 2;
    final length = bytes[pos];
    final wrappedKey = bytes.sublist(pos + 1, pos + length + 1);

    return ECDHSessionKeyParams(ephemeralKey, wrappedKey);
  }

  static Future<ECDHSessionKeyParams> encryptSessionKey(
    final ECDHPublicParams publicParams,
    final SessionKey sessionKey,
    final Uint8List fingerprint,
  ) async {
    final BigInt ephemeralKey;
    final Uint8List sharedKey;

    /// Generate the ephemeral key
    switch (publicParams.curve) {
      case CurveInfo.curve25519:
        final privateKey = nacl.PrivateKey.fromSeed(
          Helper.secureRandom().nextBytes(TweetNaCl.seedSize),
        );
        ephemeralKey = privateKey.publicKey.asTypedList.toBigIntWithSign(1);
        sharedKey = TweetNaCl.crypto_scalarmult(
          Uint8List(TweetNaCl.sharedKeyLength),
          privateKey.asTypedList,
          publicParams.q.toUnsignedBytes().sublist(1),
        );
        break;
      case CurveInfo.ed25519:
        throw UnsupportedError(
          'Curve ${publicParams.curve.name} is unsupported for ephemeral key generation.',
        );
      default:
        final parameters = ECDomainParameters(publicParams.curve.name.toLowerCase());
        final keyGen = KeyGenerator('EC')
          ..init(
            ParametersWithRandom(
              ECKeyGeneratorParameters(parameters),
              Helper.secureRandom(),
            ),
          );
        final keyPair = keyGen.generateKeyPair();
        final agreement = ECDHBasicAgreement()
          ..init(
            keyPair.privateKey as ECPrivateKey,
          );
        sharedKey = agreement
            .calculateAgreement(ECPublicKey(
              parameters.curve.decodePoint(publicParams.q.toUnsignedBytes()),
              parameters,
            ))
            .toUnsignedBytes();
        final publicKey = keyPair.publicKey as ECPublicKey;
        ephemeralKey = publicKey.Q!.getEncoded(false).toBigIntWithSign(1);
    }

    final keyWrapper = _selectKeyWrapper(publicParams.kdfSymmetric);
    final wrappedKey = await keyWrapper.wrap(
      _kdf(
        publicParams.kdfHash,
        sharedKey,
        _buildEcdhParam(publicParams, fingerprint),
        (publicParams.kdfSymmetric.keySize + 7) >> 3,
      ),
      _pkcs5Encode(Uint8List.fromList([
        ...sessionKey.encode(),
        ...sessionKey.computeChecksum(),
      ])),
    );

    return ECDHSessionKeyParams(
      ephemeralKey,
      wrappedKey,
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...ephemeralKey.bitLength.pack16(),
        ...ephemeralKey.toUnsignedBytes(),
        wrappedKey.lengthInBytes,
        ...wrappedKey,
      ]);

  Future<SessionKey> decrypt(
    final ECSecretParams secretParams,
    final ECDHPublicParams publicParams,
    final Uint8List fingerprint,
  ) async {
    final Uint8List sharedKey;
    switch (publicParams.curve) {
      case CurveInfo.curve25519:
        sharedKey = TweetNaCl.crypto_scalarmult(
          Uint8List(TweetNaCl.sharedKeyLength),
          Uint8List.fromList(secretParams.d.toUnsignedBytes().reversed.toList()),
          ephemeralKey.toUnsignedBytes(),
        );
        break;
      case CurveInfo.ed25519:
        throw UnsupportedError(
          'Curve ${publicParams.curve.name} is unsupported for key agreement calculation.',
        );
      default:
        final parameters = ECDomainParameters(publicParams.curve.name.toLowerCase());
        final privateKey = ECPrivateKey(secretParams.d, parameters);
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

    final keyWrapper = _selectKeyWrapper(publicParams.kdfSymmetric);
    return decodeSessionKey(_pkcs5Decode(
      await keyWrapper.unwrap(
        _kdf(
          publicParams.kdfHash,
          sharedKey,
          _buildEcdhParam(publicParams, fingerprint),
          (publicParams.kdfSymmetric.keySize + 7) >> 3,
        ),
        wrappedKey,
      ),
    ));
  }

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
  static Uint8List _buildEcdhParam(
    final ECDHPublicParams publicParams,
    final Uint8List fingerprint,
  ) =>
      Uint8List.fromList([
        ...publicParams.oid.encode().sublist(1),
        KeyAlgorithm.ecdh.value,
        0x3,
        publicParams.reserved,
        publicParams.kdfHash.value,
        publicParams.kdfSymmetric.value,
        ..._anonymousSender,
        ...fingerprint.sublist(0, 20),
      ]);

  /// Add pkcs5 padding to a message
  static Uint8List _pkcs5Encode(final Uint8List message) {
    final c = 8 - (message.lengthInBytes % 8);
    return Uint8List.fromList(List.filled(message.length + c, c))..setAll(0, message);
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

  static KeyWrap _selectKeyWrapper(SymmetricAlgorithm symmetric) {
    switch (symmetric) {
      case SymmetricAlgorithm.camellia128:
      case SymmetricAlgorithm.camellia192:
      case SymmetricAlgorithm.camellia256:
        return CamelliaKeyWrap();
      default:
        return AesKeyWrap();
    }
  }
}
