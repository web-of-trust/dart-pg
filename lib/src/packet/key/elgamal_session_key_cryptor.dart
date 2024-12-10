/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../../common/helpers.dart';
import '../../cryptor/asymmetric/elgamal.dart';
import '../../type/secret_key_material.dart';
import 'elgamal_secret_material.dart';
import 'session_key_cryptor.dart';

/// ElGamal session key cryptor class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ElGamalSessionKeyCryptor extends SessionKeyCryptor {
  /// MPI of ElGamal (Diffie-Hellman) value g**k mod p.
  final BigInt gamma;

  /// MPI of ElGamal (Diffie-Hellman) value m * y**k mod p.
  final BigInt phi;

  ElGamalSessionKeyCryptor(this.gamma, this.phi);

  factory ElGamalSessionKeyCryptor.fromBytes(final Uint8List bytes) {
    final gamma = Helper.readMPI(bytes);
    final phi = Helper.readMPI(bytes.sublist(gamma.byteLength + 2));

    return ElGamalSessionKeyCryptor(gamma, phi);
  }

  @override
  decrypt(final SecretKeyMaterialInterface key) {
    if (key is ElGamalSecretMaterial) {
      return _pkcs1Decode(SessionKeyCryptor.processInBlocks(
        ElGamalEngine()
          ..init(
            false,
            PrivateKeyParameter<ElGamalPrivateKey>(key.privateKey),
          ),
        Uint8List.fromList([
          ...gamma.toUnsignedBytes(),
          ...phi.toUnsignedBytes(),
        ]),
      ));
    } else {
      throw ArgumentError('Secret key material is not ElGamal key.');
    }
  }

  @override
  toBytes() => Uint8List.fromList([
        ...gamma.bitLength.pack16(),
        ...gamma.toUnsignedBytes(),
        ...phi.bitLength.pack16(),
        ...phi.toUnsignedBytes(),
      ]);

  static Uint8List _pkcs1Decode(final Uint8List encoded) {
    var offset = 2;
    var separatorNotFound = 1;
    for (var j = offset; j < encoded.length; j++) {
      separatorNotFound &= (encoded[j] != 0) ? 1 : 0;
      offset += separatorNotFound;
    }
    return encoded.sublist(offset + 1);
  }
}
