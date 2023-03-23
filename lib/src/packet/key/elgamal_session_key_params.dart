// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
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

  factory ElGamalSessionKeyParams.fromByteData(final Uint8List bytes) {
    final gamma = Helper.readMPI(bytes);
    final phi = Helper.readMPI(bytes.sublist(gamma.byteLength + 2));

    return ElGamalSessionKeyParams(gamma, phi);
  }

  static Future<ElGamalSessionKeyParams> encryptSessionKey(
    final ElGamalPublicKey key,
    final SessionKey sessionKey,
  ) async {
    final engine = PKCS1Encoding(ElGamalEngine())
      ..init(
        true,
        PublicKeyParameter<ElGamalPublicKey>(key),
      );
    final cipherData = SessionKeyParams.processInBlocks(
      engine,
      Uint8List.fromList([
        ...sessionKey.encode(),
        ...sessionKey.computeChecksum(),
      ]),
    );
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

  Future<SessionKey> decrypt(final ElGamalPrivateKey key) async {
    final plainData = SessionKeyParams.processInBlocks(
      ElGamalEngine()
        ..init(
          false,
          PrivateKeyParameter<ElGamalPrivateKey>(key),
        ),
      Uint8List.fromList([
        ...gamma.toUnsignedBytes(),
        ...phi.toUnsignedBytes(),
      ]),
    );
    return decodeSessionKey(_pkcs1Decode(plainData));
  }

  static _pkcs1Decode(final Uint8List encoded) {
    var offset = 2;
    var separatorNotFound = 1;
    for (var j = offset; j < encoded.length; j++) {
      separatorNotFound &= (encoded[j] != 0) ? 1 : 0;
      offset += separatorNotFound;
    }
    return encoded.sublist(offset + 1);
  }
}
