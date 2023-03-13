// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enum/armor_type.dart';
import '../helpers.dart';
import 'crc24.dart';

class Armor {
  static const version = 'Dart PG v1.0.0';
  static const comment = 'Dart Privacy Guard';

  static const messageBegin = '-----BEGIN PGP MESSAGE';
  static const signedMessageBegin = '-----BEGIN PGP SIGNED MESSAGE';
  static const messageEnd = '-----END PGP MESSAGE';

  static const publicKeyBlockBegin = '-----BEGIN PGP PUBLIC KEY BLOCK';
  static const publicKeyBlockEnd = '-----END PGP PUBLIC KEY BLOCK';

  static const privateKeyBlockBegin = '-----BEGIN PGP PRIVATE KEY BLOCK';
  static const privateKeyBlockEnd = '-----END PGP PRIVATE KEY BLOCK';

  static const signatureBegin = '-----BEGIN PGP SIGNATURE';
  static const signatureEnd = '-----END PGP SIGNATURE';

  static const endOfLine = '-----\n';

  static const splitPattern = r'^-----[^-]+-----$';
  static const emptyLinePattern = r'^[ \f\r\t\u00a0\u2000-\u200a\u202f\u205f\u3000]*$';
  static const headerPattern = r'^([^\s:]|[^\s:][^:]*[^\s:]): .+$';
  static const beginPattern =
      r'^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$';

  final ArmorType type;

  final Uint8List data;

  final List<String> headers;

  final String text;

  Armor(
    this.type,
    this.data, {
    this.text = '',
    this.headers = const [],
  });

  /// Dearmor an OpenPGP armored message;
  /// Verify the checksum and return the encoded bytes
  factory Armor.decode(
    final String armored, [
    final bool checksumRequired = true,
  ]) {
    var textDone = false;
    var checksum = '';
    ArmorType? type;

    final headers = <String>[];
    final textLines = <String>[];
    final dataLines = <String>[];

    final lines = LineSplitter.split(armored);
    for (final line in lines) {
      if (type == null && splitPattern.hasMatch(line)) {
        type = _getType(line);
      } else {
        if (headerPattern.hasMatch(line)) {
          headers.add(line);
        } else if (!textDone && type == ArmorType.signedMessage) {
          if (!splitPattern.hasMatch(line)) {
            textLines.add(line.replaceAll(RegExp(r'^- '), ''));
          } else {
            textDone = true;
          }
        } else if (!splitPattern.hasMatch(line)) {
          if (emptyLinePattern.hasMatch(line)) {
            continue;
          }
          if (line.startsWith('=')) {
            checksum = line.substring(1);
          } else {
            dataLines.add(line);
          }
        }
      }
    }

    final text = textLines.join('\r\n').trim();
    final data = base64.decode(dataLines.join().trim());

    if ((checksum != _crc24Checksum(data)) && (checksum.isNotEmpty || checksumRequired)) {
      throw StateError('Ascii armor integrity check failed');
    }

    return Armor(type ?? ArmorType.multipartSection, data, headers: headers, text: text);
  }

  /// Armor an OpenPGP binary packet block
  static String encode(
    final ArmorType type,
    final Uint8List data, {
    final String text = '',
    final String hashAlgo = '',
    final int partIndex = 0,
    final int partTotal = 0,
    final String customComment = '',
  }) {
    final List<String> result;
    switch (type) {
      case ArmorType.multipartSection:
        result = [
          '$messageBegin, PART $partIndex/$partTotal$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$messageEnd, PART $partIndex/$partTotal$endOfLine',
        ];
        break;
      case ArmorType.multipartLast:
        result = [
          '$messageBegin, PART $partIndex$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$messageEnd, PART $partIndex$endOfLine',
        ];
        break;
      case ArmorType.signedMessage:
        result = [
          '$signedMessageBegin$endOfLine',
          'Hash: $hashAlgo\n\n',
          '${text.replaceAll(RegExp(r'^-', multiLine: true), '- -')}\n',
          '$signatureBegin$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$signatureEnd$endOfLine',
        ];
        break;
      case ArmorType.message:
        result = [
          '$messageBegin$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$messageEnd$endOfLine',
        ];
        break;
      case ArmorType.publicKey:
        result = [
          '$publicKeyBlockBegin$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$publicKeyBlockEnd$endOfLine',
        ];
        break;
      case ArmorType.privateKey:
        result = [
          '$privateKeyBlockBegin$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$privateKeyBlockEnd$endOfLine',
        ];
        break;
      case ArmorType.signature:
        result = [
          '$signatureBegin$endOfLine',
          _addHeader(customComment),
          '${_base64Encode(data)}\n',
          '=${_crc24Checksum(data)}\n',
          '$signatureEnd$endOfLine',
        ];
        break;
      default:
        result = [];
    }
    return result.join();
  }

  static ArmorType _getType(final String text) {
    final matches = RegExp(beginPattern).allMatches(text);
    if (matches.isEmpty) {
      throw ArgumentError('Unknown ASCII armor type');
    }
    final match = matches.elementAt(0)[0]!;
    if (r'MESSAGE, PART \d+\/\d+'.hasMatch(match)) {
      return ArmorType.multipartSection;
    } else if (r'MESSAGE, PART \d+'.hasMatch(match)) {
      return ArmorType.multipartLast;
    } else if (r'SIGNED MESSAGE'.hasMatch(match)) {
      return ArmorType.signedMessage;
    } else if (r'MESSAGE'.hasMatch(match)) {
      return ArmorType.message;
    } else if (r'PUBLIC KEY BLOCK'.hasMatch(match)) {
      return ArmorType.publicKey;
    } else if (r'PRIVATE KEY BLOCK'.hasMatch(match)) {
      return ArmorType.privateKey;
    } else if (r'SIGNATURE'.hasMatch(match)) {
      return ArmorType.signature;
    }
    return ArmorType.multipartSection;
  }

  static String _addHeader([final String customComment = '']) {
    final headers = <String>[];
    headers.add('Version: $version\n');
    headers.add('Comment: $comment\n');
    if (customComment.trim().isNotEmpty) {
      headers.add('Comment: $customComment\n');
    }
    headers.add('\n');
    return headers.join();
  }

  static String _base64Encode(final Uint8List data) {
    return base64.encode(data).chunk(76).join('\n');
  }

  static String _crc24Checksum(final Uint8List data) {
    return Crc24.base64Calculate(data);
  }
}
