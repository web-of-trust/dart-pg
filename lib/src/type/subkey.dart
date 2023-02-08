// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/signature.dart';
import '../packet/subkey_packet.dart';
import 'key.dart';

/// Class that represents a subkey packet and the relevant signatures.
class Subkey {
  /// subkey packet to hold in the Subkey
  final SubkeyPacket keyPacket;

  /// reference to main Key object, containing the primary key packet corresponding to the subkey
  final Key mainKey;

  final List<SignaturePacket> bindingSignatures;

  final List<SignaturePacket> revocationSignatures;

  Subkey(
    this.keyPacket,
    this.mainKey, {
    this.bindingSignatures = const [],
    this.revocationSignatures = const [],
  });
}
