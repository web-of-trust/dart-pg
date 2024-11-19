/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/enum/literal_format.dart';

/// Literal data interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class LiteralDataInterface {
  LiteralFormat get format;

  String get filename;

  DateTime get time;

  Uint8List get binary;

  String get text;

  Uint8List get header;

  Uint8List get signBytes;
}
