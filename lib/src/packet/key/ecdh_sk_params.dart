// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';
import 'sk_params.dart';

/// ECDH encrypted session key params
class ECDHSkParams extends SkParams {
  /// MPI containing the ephemeral key used to establish the shared secret
  final BigInt publicKey;

  /// ECDH symmetric key
  Uint8List wrappedKey;

  ECDHSkParams(this.publicKey, this.wrappedKey);

  factory ECDHSkParams.fromPacketData(Uint8List bytes) {
    final ephemeralKey = Helper.readMPI(bytes);

    var pos = ephemeralKey.byteLength + 2;
    final length = bytes[pos++];
    final symkey = bytes.sublist(pos, pos + length);

    return ECDHSkParams(ephemeralKey, symkey);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...publicKey.bitLength.pack16(),
        ...publicKey.toUnsignedBytes(),
        wrappedKey.lengthInBytes,
        ...wrappedKey,
      ]);
}
