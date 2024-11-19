/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Literal formats enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum LiteralFormat {
  /// Binary data 'b'
  binary(98),

  /// Text data 't'
  text(116),

  /// Utf8 data 'u'
  utf8(117),

  /// MIME message body part 'm'
  mime(109);

  final int value;

  const LiteralFormat(this.value);
}
