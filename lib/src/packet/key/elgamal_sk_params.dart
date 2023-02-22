// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';
import 'sk_params.dart';

/// Elgamal encrypted session key Params
class ElGamalSkParams extends SkParams {
  /// MPI of Elgamal value g**k mod p
  final BigInt gamma;

  /// MPI of Elgamal value m * y**k mod p
  final BigInt phi;

  ElGamalSkParams(this.gamma, this.phi);

  factory ElGamalSkParams.fromPacketData(Uint8List bytes) {
    final gamma = Helper.readMPI(bytes);
    final phi = Helper.readMPI(bytes.sublist(gamma.byteLength + 2));

    return ElGamalSkParams(gamma, phi);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...gamma.bitLength.pack16(),
        ...gamma.toUnsignedBytes(),
        ...phi.bitLength.pack16(),
        ...phi.toUnsignedBytes(),
      ]);
}
