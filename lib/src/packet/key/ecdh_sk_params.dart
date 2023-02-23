// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';
import 'sk_params.dart';

/// Algorithm Specific Params for ECDH encryption
class ECDHSkParams extends SkParams {
  /// MPI containing the ephemeral key used to establish the shared secret
  final BigInt ephemeralKey;

  /// ECDH symmetric key
  Uint8List wrappedKey;

  ECDHSkParams(this.ephemeralKey, this.wrappedKey);

  factory ECDHSkParams.fromPacketData(Uint8List bytes) {
    final ephemeralKey = Helper.readMPI(bytes);

    var pos = ephemeralKey.byteLength + 2;
    final length = bytes[pos++];
    final wrappedKey = bytes.sublist(pos, pos + length);

    return ECDHSkParams(ephemeralKey, wrappedKey);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...ephemeralKey.bitLength.pack16(),
        ...ephemeralKey.toUnsignedBytes(),
        wrappedKey.lengthInBytes,
        ...wrappedKey,
      ]);
}
