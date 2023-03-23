// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
import '../../helpers.dart';
import 'session_key.dart';
import 'session_key_params.dart';

/// Algorithm Specific Params for RSA encryption
class RSASessionKeyParams extends SessionKeyParams {
  /// multiprecision integer (MPI) of RSA encrypted value m**e mod n.
  final BigInt encrypted;

  RSASessionKeyParams(this.encrypted);

  factory RSASessionKeyParams.fromByteData(
    final Uint8List bytes,
  ) =>
      RSASessionKeyParams(Helper.readMPI(bytes));

  static Future<RSASessionKeyParams> encryptSessionKey(
    final RSAPublicKey key,
    final SessionKey sessionKey,
  ) async {
    return RSASessionKeyParams(
      SessionKeyParams.processInBlocks(
        AsymmetricBlockCipher('RSA/PKCS1')
          ..init(
            true,
            PublicKeyParameter<RSAPublicKey>(key),
          ),
        Uint8List.fromList([
          ...sessionKey.encode(),
          ...sessionKey.computeChecksum(),
        ]),
      ).toBigIntWithSign(1),
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...encrypted.bitLength.pack16(),
        ...encrypted.toUnsignedBytes(),
      ]);

  Future<SessionKey> decrypt(final RSAPrivateKey key) async {
    return decodeSessionKey(
      SessionKeyParams.processInBlocks(
        AsymmetricBlockCipher('RSA/PKCS1')
          ..init(
            false,
            PrivateKeyParameter<RSAPrivateKey>(key),
          ),
        encrypted.toUnsignedBytes(),
      ),
    );
  }
}
