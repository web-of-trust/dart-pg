// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';
import 'key_params.dart';

class ElGamalSecretParams extends KeyParams {
  /// Elgamal secret exponent x.
  final BigInt secretExponent;

  ElGamalSecretParams(this.secretExponent);

  factory ElGamalSecretParams.fromPacketData(final Uint8List bytes) => ElGamalSecretParams(Helper.readMPI(bytes));

  @override
  Uint8List encode() => Uint8List.fromList([...secretExponent.bitLength.pack16(), ...secretExponent.toUnsignedBytes()]);
}
