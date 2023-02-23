// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';
import 'sk_params.dart';

/// Algorithm Specific Params for RSA encryption
class RSASkParams extends SkParams {
  /// multiprecision integer (MPI) of RSA encrypted value m**e mod n.
  final BigInt encrypted;

  RSASkParams(this.encrypted);

  factory RSASkParams.fromPacketData(Uint8List bytes) => RSASkParams(Helper.readMPI(bytes));

  @override
  Uint8List encode() => Uint8List.fromList([
        ...encrypted.bitLength.pack16(),
        ...encrypted.toUnsignedBytes(),
      ]);
}
