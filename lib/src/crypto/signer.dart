// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/key/rsa_public_params.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:pointycastle/impl.dart';

import '../enums.dart';
import '../helpers.dart';
import '../key/dsa_public_params.dart';
import '../key/dsa_secret_params.dart';
import '../key/ec_public_params.dart';
import '../key/ec_secret_params.dart';
import '../key/key_params.dart';
import '../key/rsa_secret_params.dart';
import 'signer/dsa.dart';

class Signer {
  /// Creates a signature on data using specified algorithms and private key parameters.
  static Uint8List sign(
    KeyAlgorithm keyAlgorithm,
    HashAlgorithm hashAlgorithm,
    KeyParams publicParams,
    KeyParams secretParams,
    Uint8List message,
  ) {
    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final privateKey = (secretParams as RSASecretParams).privateKey;
        return _rsaSign(privateKey, hashAlgorithm, message);
      case KeyAlgorithm.dsa:
        final keyParams = publicParams as DSAPublicParams;
        final p = keyParams.primeP;
        final q = keyParams.groupOrder;
        final g = keyParams.groupGenerator;
        final x = (secretParams as DSASecretParams).secretExponent;
        final privateKey = DSAPrivateKey(x, p, q, g);
        return _dsaSign(privateKey, hashAlgorithm, message);
      case KeyAlgorithm.ecdsa:
        final d = (secretParams as ECSecretParams).d;
        final publicKey = (publicParams as ECPublicParams).publicKey;
        final privateKey = ECPrivateKey(d, publicKey.parameters);
        return _ecdsaSign(privateKey, hashAlgorithm, message);
      default:
        throw Exception('Unknown signature algorithm.');
    }
  }

  /// Verifies the signature provided for data using specified algorithms and public key parameters.
  static bool verify(
    KeyAlgorithm keyAlgorithm,
    HashAlgorithm hashAlgorithm,
    KeyParams publicParams,
    Uint8List message,
    Uint8List signature,
  ) {
    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final publicKey = (publicParams as RSAPublicParams).publicKey;
        return _rsaVerify(publicKey, hashAlgorithm, message, signature);
      case KeyAlgorithm.dsa:
        final publicKey = (publicParams as DSAPublicParams).publicKey;
        return _dsaVerify(publicKey, hashAlgorithm, message, signature);
      case KeyAlgorithm.ecdsa:
        final publicKey = (publicParams as ECPublicParams).publicKey;
        return _ecdsaVerify(publicKey, hashAlgorithm, message, signature);
      default:
        throw Exception('Unknown signature algorithm.');
    }
  }

  static Uint8List _rsaSign(pc.RSAPrivateKey privateKey, HashAlgorithm hashAlgorithm, Uint8List message) {
    final signer = pc.Signer('${hashAlgorithm.digestName}/RSA')
      ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(message) as RSASignature;
    return signature.bytes;
  }

  static bool _rsaVerify(
    pc.RSAPublicKey publicKey,
    HashAlgorithm hashAlgorithm,
    Uint8List message,
    Uint8List signature,
  ) {
    final signer = pc.Signer('${hashAlgorithm.digestName}/RSA')
      ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));
    return signer.verifySignature(message, RSASignature(signature));
  }

  static Uint8List _dsaSign(DSAPrivateKey privateKey, HashAlgorithm hashAlgorithm, Uint8List message) {
    final signer = DSASigner(pc.Digest(hashAlgorithm.digestName))
      ..init(true, pc.PrivateKeyParameter<DSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(message);
    return signature.encode();
  }

  static bool _dsaVerify(
    DSAPublicKey publicKey,
    HashAlgorithm hashAlgorithm,
    Uint8List message,
    Uint8List signature,
  ) {
    final signer = DSASigner(pc.Digest(hashAlgorithm.digestName))
      ..init(false, pc.PublicKeyParameter<DSAPublicKey>(publicKey));

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, DSASignature(r, s));
  }

  static Uint8List _ecdsaSign(ECPrivateKey privateKey, HashAlgorithm hashAlgorithm, Uint8List message) {
    final signer = pc.Signer('${hashAlgorithm.digestName}/ECDSA')
      ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey));
    final signature = signer.generateSignature(message) as ECSignature;
    return Uint8List.fromList([
      ...signature.r.bitLength.pack16(),
      ...signature.r.toUnsignedBytes(),
      ...signature.s.bitLength.pack16(),
      ...signature.s.toUnsignedBytes(),
    ]);
  }

  static bool _ecdsaVerify(
    ECPublicKey publicKey,
    HashAlgorithm hashAlgorithm,
    Uint8List message,
    Uint8List signature,
  ) {
    final signer = pc.Signer('${hashAlgorithm.digestName}/ECDSA')
      ..init(false, pc.PublicKeyParameter<ECPublicKey>(publicKey));

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, ECSignature(r, s));
  }
}
