// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/asymmetric/elgamal.dart';
import '../../helpers.dart';
import 'session_key.dart';
import 'session_key_params.dart';

/// Algorithm Specific Params for Elgamal encryption
class ElGamalSessionKeyParams extends SessionKeyParams {
  /// MPI of Elgamal (Diffie-Hellman) value g**k mod p.
  final BigInt gamma;

  /// MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
  final BigInt phi;

  ElGamalSessionKeyParams(this.gamma, this.phi);

  factory ElGamalSessionKeyParams.fromPacketData(final Uint8List bytes) {
    final gamma = Helper.readMPI(bytes);
    final phi = Helper.readMPI(bytes.sublist(gamma.byteLength + 2));

    return ElGamalSessionKeyParams(gamma, phi);
  }

  factory ElGamalSessionKeyParams.encryptSessionKey(final ElGamalPublicKey key, final SessionKey sessionKey) {
    final engine = ElGamalEngine()..init(true, PublicKeyParameter<ElGamalPublicKey>(key));
    final cipherData = Uint8List(engine.outputBlockSize);
    final plainData = Helper.emeEncode(
      Uint8List.fromList([
      ...sessionKey.encode(),
      ...sessionKey.checksum(),
      ]),
      key.prime.byteLength,
    );
    engine.processBlock(plainData, 0, plainData.length, cipherData, 0);
    return ElGamalSessionKeyParams(
      cipherData.sublist(0, engine.outputBlockSize ~/ 2).toBigIntWithSign(1),
      cipherData.sublist(engine.outputBlockSize ~/ 2).toBigIntWithSign(1),
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...gamma.bitLength.pack16(),
        ...gamma.toUnsignedBytes(),
        ...phi.bitLength.pack16(),
        ...phi.toUnsignedBytes(),
      ]);

  SessionKey decrypt(final ElGamalPrivateKey key) {
    final engine = ElGamalEngine()..init(false, PrivateKeyParameter<ElGamalPrivateKey>(key));
    final plainData = Uint8List(engine.outputBlockSize);
    final cipherData = Uint8List.fromList([
      ...gamma.toUnsignedBytes(),
      ...phi.toUnsignedBytes(),
    ]);
    engine.processBlock(cipherData, 0, cipherData.length, plainData, 0);
    return decodeSessionKey(Helper.emeDecode(plainData));
  }
}
