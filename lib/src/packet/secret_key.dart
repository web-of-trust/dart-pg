// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../key/s2k.dart';
import 'contained_packet.dart';
import 'public_key.dart';

/// SecretKey represents a possibly encrypted private key.
/// See RFC 4880, section 5.5.3.
class SecretKey extends ContainedPacket {
  static const tag = PacketTag.secretKey;

  final PublicKey publicKey;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2kUsage s2kUsage;

  final S2K s2k;

  final Uint8List iv;

  final Uint8List keyData;

  SecretKey(this.publicKey, this.symmetricAlgorithm, this.s2kUsage, this.s2k, this.iv, this.keyData);

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [...publicKey.toPacketData(), s2kUsage.value];
    if (s2kUsage == S2kUsage.checksum || s2kUsage == S2kUsage.sha1) {
      bytes.addAll([symmetricAlgorithm.value, ...s2k.encode()]);
    }
    bytes.addAll(iv);
    bytes.addAll(keyData);
    return Uint8List.fromList(bytes);
  }
}
