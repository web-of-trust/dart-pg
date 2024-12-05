/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/enum/literal_format.dart';

/// Literal data interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class LiteralDataInterface {
  /// Get literal format
  LiteralFormat get format;

  /// Get filename
  String get filename;

  /// Get time
  DateTime get time;

  /// Get binary data
  Uint8List get binary;

  /// Get text data
  String get text;

  /// Get header
  Uint8List get header;

  /// Get bytes for sign
  Uint8List get signBytes;
}
