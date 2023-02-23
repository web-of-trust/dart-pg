// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../crypto/asymmetric/elgamal.dart';
import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';
import 'contained_packet.dart';
import 'key/aes_key_wrapper.dart';
import 'key/key_id.dart';
import 'key/key_params.dart';
import 'key/sk_params.dart';
import 'key_packet.dart';

/// PublicKeyEncryptedSessionKey represents a public-key encrypted session key.
/// See RFC 4880, section 5.1.
class PublicKeyEncryptedSessionKeyPacket extends ContainedPacket {
  static const _anonymousSender = 'Anonymous Sender    ';

  final int version;

  final KeyID publicKeyID;

  final KeyAlgorithm publicKeyAlgorithm;

  /// Encrypted session key params
  final SkParams sessionKeyParams;

  /// Session key
  final Uint8List sessionKey;

  /// Algorithm to encrypt the message with
  final SymmetricAlgorithm sessionKeySymmetric;

  PublicKeyEncryptedSessionKeyPacket(
    this.publicKeyID,
    this.publicKeyAlgorithm,
    this.sessionKeyParams,
    this.sessionKey, {
    this.sessionKeySymmetric = OpenPGP.preferredSymmetric,
    this.version = OpenPGP.pkeskVersion,
    super.tag = PacketTag.publicKeyEncryptedSessionKey,
  });

  factory PublicKeyEncryptedSessionKeyPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    if (version != OpenPGP.pkeskVersion) {
      throw UnsupportedError('Version $version of the PKESK packet is unsupported.');
    }

    final keyID = bytes.sublist(pos, pos + 8);
    pos += 8;

    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;

    final SkParams params;
    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
        params = RSASkParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.elgamal:
        params = ElGamalSkParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdh:
        params = ECDHSkParams.fromPacketData(bytes.sublist(pos));
        break;
      default:
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
    }

    return PublicKeyEncryptedSessionKeyPacket(
      KeyID(keyID),
      keyAlgorithm,
      params,
      Uint8List.fromList([]),
      version: version,
    );
  }

  factory PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
    final Uint8List sessionKey,
    final PublicKeyPacket key, {
    final SymmetricAlgorithm sessionKeySymmetric = OpenPGP.preferredSymmetric,
  }) {
    final data = Uint8List.fromList([
      sessionKeySymmetric.value,
      ...sessionKey,
      ...Helper.calculateChecksum(sessionKey),
    ]);

    final SkParams params;
    switch (key.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
        final publicKey = (key.publicParams as RSAPublicParams).publicKey;
        params = _rsaEncrypt(publicKey, data);
        break;
      case KeyAlgorithm.elgamal:
        final publicKey = (key.publicParams as ElGamalPublicParams).publicKey;
        params = _elgamalEncrypt(publicKey, data);
        break;
      case KeyAlgorithm.ecdh:
        params = _ecdhEncrypt((key.publicParams as ECDHPublicParams), data, key.fingerprint.hexToBytes());
        break;
      default:
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
    }
    return PublicKeyEncryptedSessionKeyPacket(
      key.keyID,
      key.algorithm,
      params,
      sessionKey,
      sessionKeySymmetric: sessionKeySymmetric,
    );
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      ...publicKeyID.id,
      publicKeyAlgorithm.value,
      ...sessionKeyParams.encode(),
    ]);
  }

  PublicKeyEncryptedSessionKeyPacket decrypt(final SecretKeyPacket key) {
    // check that session key algo matches the secret key algo
    if (publicKeyAlgorithm == key.algorithm) {
      throw StateError('PKESK decryption error');
    }

    final Uint8List decoded;
    switch (key.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
        final privateKey = (key.secretParams as RSASecretParams).privateKey;
        decoded = _rsaDecrypt(privateKey, sessionKeyParams.encode());
        break;
      case KeyAlgorithm.elgamal:
        final publicKey = (key.publicParams as ElGamalPublicParams).publicKey;
        final secretExponent = (key.secretParams as ElGamalSecretParams).secretExponent;
        decoded = _elgamalDecrypt(
          ElGamalPrivateKey(secretExponent, publicKey.prime, publicKey.generator),
          sessionKeyParams.encode(),
        );
        break;
      case KeyAlgorithm.ecdh:
        final publicParams = key.publicParams as ECDHPublicParams;
        final privateKey = ECPrivateKey(
          (key.secretParams as ECSecretParams).d,
          publicParams.publicKey.parameters,
        );
        decoded = _ecdhDecrypt(
          privateKey,
          publicParams,
          sessionKeyParams as ECDHSkParams,
          key.fingerprint.hexToBytes(),
        );
        break;
      default:
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
    }

    final sessionKeySymmetric = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == decoded[0]);
    final sessionKey = decoded.sublist(1, decoded.length - 2);
    final checksum = decoded.sublist(decoded.length - 2);
    final computedChecksum = Helper.calculateChecksum(sessionKey);
    final isValidChecksum = (computedChecksum[0] == checksum[0]) && (computedChecksum[1] == checksum[1]);
    if (!isValidChecksum) {
      throw StateError('PKESK decryption error');
    }

    return PublicKeyEncryptedSessionKeyPacket(
      publicKeyID,
      publicKeyAlgorithm,
      sessionKeyParams,
      sessionKey,
      sessionKeySymmetric: sessionKeySymmetric,
    );
  }

  static RSASkParams _rsaEncrypt(final RSAPublicKey key, final Uint8List plainData) {
    final engine = AsymmetricBlockCipher('RSA')..init(true, PublicKeyParameter<RSAPublicKey>(key));
    return RSASkParams(_processInBlocks(engine, plainData).toBigIntWithSign(1));
  }

  static Uint8List _rsaDecrypt(final RSAPrivateKey key, final Uint8List cipherData) {
    final engine = AsymmetricBlockCipher('RSA')..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
    return _processInBlocks(engine, cipherData);
  }

  static ElGamalSkParams _elgamalEncrypt(final ElGamalPublicKey key, final Uint8List plainData) {
    final engine = ElGamalEngine()..init(true, PublicKeyParameter<ElGamalPublicKey>(key));
    final cipherData = Uint8List(engine.outputBlockSize);
    engine.processBlock(plainData, 0, plainData.length, cipherData, 0);
    return ElGamalSkParams(
      cipherData.sublist(0, engine.outputBlockSize ~/ 2).toBigIntWithSign(1),
      cipherData.sublist(engine.outputBlockSize ~/ 2).toBigIntWithSign(1),
    );
  }

  static Uint8List _elgamalDecrypt(final ElGamalPrivateKey key, final Uint8List cipherData) {
    final engine = ElGamalEngine()..init(true, PrivateKeyParameter<ElGamalPrivateKey>(key));
    final plainData = Uint8List(engine.outputBlockSize);
    engine.processBlock(cipherData, 0, cipherData.length, plainData, 0);
    return plainData;
  }

  static ECDHSkParams _ecdhEncrypt(
    final ECDHPublicParams publicParams,
    final Uint8List plainData,
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
      _pkcs5Encode(plainData),
    );

    return ECDHSkParams(
      publicKey.Q!.getEncoded(false).toBigIntWithSign(1),
      wrappedKey,
    );
  }

  static Uint8List _ecdhDecrypt(
    final ECPrivateKey privateKey,
    final ECDHPublicParams publicParams,
    final ECDHSkParams sessionKeyParams,
    final Uint8List fingerprint,
  ) {
    final point = privateKey.parameters!.curve.decodePoint(sessionKeyParams.publicKey.toUnsignedBytes());
    final publicKey = ECPublicKey(point, privateKey.parameters);
    final agreement = ECDHBasicAgreement()..init(privateKey);
    final sharedKey = agreement.calculateAgreement(publicKey);

    final param = _buildEcdhParam(publicParams, fingerprint);
    final keySize = (publicParams.kdfSymmetric.keySize + 7) >> 3;

    return _pkcs5Decode(
      AesKeyWrapper.unwrap(
        _kdf(publicParams.kdfHash, sharedKey, keySize, param),
        sessionKeyParams.wrappedKey,
      ),
    );
  }

  /// Key Derivation Function (RFC 6637)
  static Uint8List _kdf(HashAlgorithm hash, BigInt sharedKey, int keySize, Uint8List param) {
    return Helper.hashDigest(
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
  }

  /// Build Param for ECDH algorithm (RFC 6637)
  static Uint8List _buildEcdhParam(final ECDHPublicParams publicParams, Uint8List fingerprint) {
    return Uint8List.fromList([
      ...publicParams.oid.encode().sublist(1),
      KeyAlgorithm.ecdh.value,
      0x3,
      publicParams.reserved,
      publicParams.kdfHash.value,
      publicParams.kdfSymmetric.value,
      ..._anonymousSender.stringToBytes(),
      ...fingerprint.sublist(0, 20),
    ]);
  }

  static Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = input.length ~/ engine.inputBlockSize + ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inputOffset = 0;
    var outputOffset = 0;
    while (inputOffset < input.length) {
      final chunkSize =
          (inputOffset + engine.inputBlockSize <= input.length) ? engine.inputBlockSize : input.length - inputOffset;

      outputOffset += engine.processBlock(input, inputOffset, chunkSize, output, outputOffset);

      inputOffset += chunkSize;
    }

    return (output.length == outputOffset) ? output : output.sublist(0, outputOffset);
  }

  static Uint8List _pkcs5Encode(Uint8List message) {
    final c = 8 - (message.lengthInBytes % 8);
    return Uint8List.fromList(List.filled(message.length + c, c))..setAll(0, message);
  }

  static Uint8List _pkcs5Decode(Uint8List message) {
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
