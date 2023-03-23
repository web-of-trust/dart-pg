// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

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
