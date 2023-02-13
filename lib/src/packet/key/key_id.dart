// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../helpers.dart';

class KeyID {
  final Uint8List id;

  KeyID(this.id);

  factory KeyID.fromString(String hex) => KeyID(hex.hexToBytes());

  factory KeyID.wildcard() => KeyID(Uint8List.fromList(List.filled(8, 0, growable: false)));

  @override
  String toString() => id.toHexadecimal();
}