// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../openpgp.dart';
import 'key/key_pair_generator.dart';
import 'public_key.dart';
import 'public_subkey.dart';
import 'secret_key.dart';
import 'secret_subkey.dart';

class KeyPacketGenerator {
  static const keyVersion = OpenPGP.version5Keys ? 5 : 4;

  static SecretKeyPacket generateSecretKey(
    final KeyAlgorithm algorithm, {
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveOid curveOid = OpenPGP.preferredEcCurve,
    final DateTime? date,
  }) {
    final keyPair = KeyPairGenerator.generateKeyPairParams(algorithm, rsaBits: rsaBits, curveOid: curveOid);

    return SecretKeyPacket(
      PublicKeyPacket(
        keyVersion,
        date ?? DateTime.now(),
        keyPair.publicParams,
        algorithm: algorithm,
      ),
      keyPair.secretParams.encode(),
      secretParams: keyPair.secretParams,
    );
  }

  static SecretSubkeyPacket generateSecretSubkey(
    final KeyAlgorithm algorithm, {
    final int rsaBits = OpenPGP.preferredRSABits,
    final CurveOid curveOid = OpenPGP.preferredEcCurve,
    final DateTime? date,
  }) {
    final keyPair = KeyPairGenerator.generateKeyPairParams(algorithm, rsaBits: rsaBits, curveOid: curveOid);

    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        keyVersion,
        date ?? DateTime.now(),
        keyPair.publicParams,
        algorithm: algorithm,
      ),
      keyPair.secretParams.encode(),
      secretParams: keyPair.secretParams,
    );
  }
}
