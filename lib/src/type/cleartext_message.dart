// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

abstract class CleartextMessage {
  /// The cleartext of the signed message
  final String _text;

  CleartextMessage(String text) : _text = text.trimRight().replaceAll(RegExp(r'\r?\n', multiLine: true), '\r\n');

  String get text => _text;

  String get normalizeText => _text.replaceAll(RegExp(r'\r\n', multiLine: true), '\n');
}
