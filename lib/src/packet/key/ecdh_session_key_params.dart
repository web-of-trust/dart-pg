// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/hash_algorithm.dart';
import '../../enum/key_algorithm.dart';
import '../../helpers.dart';
import 'aes_key_wrapper.dart';
import 'ecdh_public_params.dart';
import 'session_key.dart';
import 'session_key_params.dart';

/// Algorithm Specific Params for ECDH encryption
class ECDHSessionKeyParams extends SessionKeyParams {
  /// 20 octets representing the UTF-8 encoding of the string 'Anonymous Sender    '
  static const _anonymousSender = [
    0x41,
    0x6e,
    0x6f,
    0x6e,
    0x79,
    0x6d,
    0x6f,
    0x75,
    0x73,
    0x20,
    0x53,
    0x65,
    0x6e,
    0x64,
    0x65,
    0x72,
    0x20,
    0x20,
    0x20,
    0x20,
  ];

  /// MPI containing the ephemeral key used to establish the shared secret
  final BigInt ephemeralKey;

  /// ECDH symmetric key
  final Uint8List wrappedKey;

  ECDHSessionKeyParams(this.ephemeralKey, this.wrappedKey);

  factory ECDHSessionKeyParams.fromPacketData(Uint8List bytes) {
    final ephemeralKey = Helper.readMPI(bytes);

    var pos = ephemeralKey.byteLength + 2;
    final length = bytes[pos++];
    final wrappedKey = bytes.sublist(pos, pos + length);

    return ECDHSessionKeyParams(ephemeralKey, wrappedKey);
  }

  factory ECDHSessionKeyParams.encryptSessionKey(
    final ECDHPublicParams publicParams,
    final SessionKey sessionKey,
    final Uint8List fingerprint,
  ) {
    /// Generate the ephemeral key pair
    final keyGen = KeyGenerator('EC')
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(publicParams.publicKey.parameters!),
          Helper.secureRandom(),
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    final agreement = ECDHBasicAgreement()..init(keyPair.privateKey as ECPrivateKey);
    final sharedKey = agreement.calculateAgreement(publicParams.publicKey);
    final publicKey = keyPair.publicKey as ECPublicKey;

    final param = _buildEcdhParam(publicParams, fingerprint);
    final keySize = (publicParams.kdfSymmetric.keySize + 7) >> 3;

    final wrappedKey = AesKeyWrapper.wrap(
      _kdf(publicParams.kdfHash, sharedKey, keySize, param),
      _pkcs5Encode(Uint8List.fromList([
        ...sessionKey.encode(),
        ...sessionKey.checksum(),
      ])),
    );

    return ECDHSessionKeyParams(
      publicKey.Q!.getEncoded(false).toBigIntWithSign(1),
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

  SessionKey decrypt(
    final ECPrivateKey privateKey,
    final ECDHPublicParams publicParams,
    final Uint8List fingerprint,
  ) {
    final point = privateKey.parameters!.curve.decodePoint(ephemeralKey.toUnsignedBytes());
    final publicKey = ECPublicKey(point, privateKey.parameters);
    final agreement = ECDHBasicAgreement()..init(privateKey);
    final sharedKey = agreement.calculateAgreement(publicKey);

    final param = _buildEcdhParam(publicParams, fingerprint);
    final keySize = (publicParams.kdfSymmetric.keySize + 7) >> 3;
    return decodeSessionKey(_pkcs5Decode(
      AesKeyWrapper.unwrap(
        _kdf(publicParams.kdfHash, sharedKey, keySize, param),
        wrappedKey,
      ),
    ));
  }

  /// Key Derivation Function (RFC 6637)
  static Uint8List _kdf(
    final HashAlgorithm hash,
    final BigInt sharedKey,
    final int keySize,
    final Uint8List param,
  ) =>
      Helper.hashDigest(
        Uint8List.fromList([
          0,
          0,
          0,
          1,
          ...sharedKey.toUnsignedBytes(),
          ...param,
        ]),
        hash,
      ).sublist(0, keySize);

  /// Build Param for ECDH algorithm (RFC 6637)
  static Uint8List _buildEcdhParam(final ECDHPublicParams publicParams, final Uint8List fingerprint) =>
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
}
