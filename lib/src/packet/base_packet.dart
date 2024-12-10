/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:math';
import 'dart:typed_data';

import '../common/extensions.dart';
import '../enum/packet_type.dart';
import '../type/packet.dart';

export '../enum/packet_type.dart';
export 'aead_encrypted_data.dart';
export 'compressed_data.dart';
export 'literal_data.dart';
export 'marker.dart';
export 'one_pass_signature.dart';
export 'packet_list.dart';
export 'packet_reader.dart';
export 'padding.dart';
export 'public_key.dart';
export 'public_key_encrypted_session_key.dart';
export 'public_subkey.dart';
export 'secret_key.dart';
export 'secret_subkey.dart';
export 'signature.dart';
export 'signature_subpacket.dart';
export 'sym_encrypted_data.dart';
export 'sym_encrypted_integrity_protected_data.dart';
export 'sym_encrypted_session_key.dart';
export 'trust.dart';
export 'user_attribute.dart';
export 'user_id.dart';

/// Base abstract packet class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BasePacket implements PacketInterface {
  static const partialMinSize = 512;
  static const partialMaxSize = 1024;

  @override
  final PacketType type;

  BasePacket(this.type);

  @override
  encode() {
    switch (type) {
      case PacketType.aeadEncryptedData:
      case PacketType.compressedData:
      case PacketType.literalData:
      case PacketType.symEncryptedData:
      case PacketType.symEncryptedIntegrityProtectedData:
        return _partialEncode();
      default:
        return Uint8List.fromList([
          type.value | 0xc0,
          ..._simpleLength(data.length),
          ...data,
        ]);
    }
  }

  /// Encode package to the openpgp partial body specifier
  Uint8List _partialEncode() {
    final partialData = <int>[];
    var bodyData = data;
    var dataLengh = bodyData.length;
    while (dataLengh >= partialMinSize) {
      final maxSize = min(partialMaxSize, dataLengh);
      final powerOf2 = min((log(maxSize) / ln2).toInt(), 30);
      final chunkSize = 1 << powerOf2;
      partialData.addAll(
        [
          224 + powerOf2,
          ...bodyData.sublist(0, chunkSize),
        ],
      );
      bodyData = bodyData.sublist(chunkSize);
      dataLengh = bodyData.length;
    }
    partialData.addAll([
      ..._simpleLength(dataLengh),
      ...bodyData,
    ]);
    return Uint8List.fromList([type.value | 0xc0, ...partialData]);
  }

  Uint8List _simpleLength(int length) {
    if (length < 192) {
      return Uint8List.fromList([length]);
    } else if (length < 8384) {
      return Uint8List.fromList(
        [(((length - 192) >> 8) & 0xff) + 192, length - 192],
      );
    } else {
      return Uint8List.fromList([0xff, ...length.pack32()]);
    }
  }
}
