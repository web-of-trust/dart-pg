/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../enum/armor_type.dart';
import 'config.dart';
import 'helpers.dart';

/// ASCII Armor class
/// OpenPGP's Radix-64 encoding.
/// It is composed of two parts: a base64
/// encoding of the binary data and a checksum.
/// See https://www.rfc-editor.org/rfc/rfc9580#section-6
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Armor {
  static const version = 'Dart PG v2';
  static const comment = 'The Dart OpenPGP library';

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
  static const emptyLinePattern =
      r'^[ \f\r\t\u00a0\u2000-\u200a\u202f\u205f\u3000]*$';
  static const headerPattern = r'^([^\s:]|[^\s:][^:]*[^\s:]): .+$';

  static const base64Chunk = 76;

  /// Armor type
  final ArmorType type;

  /// Armor data
  final Uint8List data;

  /// Armor headers
  final List<String> headers;

  /// Armor text
  final String text;

  Armor(
    this.type,
    this.data, {
    this.text = '',
    this.headers = const [],
  });

  /// Dearmor an OpenPGP armored message;
  /// Verify the checksum and return the encoded bytes
  factory Armor.decode(final String armored) {
    var textDone = false;
    var checksum = '';
    ArmorType? type;

    final headers = <String>[];
    final textLines = <String>[];
    final dataLines = <String>[];

    final lines = armored.split('\n');
    for (final line in lines) {
      if (type == null && splitPattern.hasMatch(line)) {
        type = ArmorType.fromBegin(line);
      } else {
        if (headerPattern.hasMatch(line)) {
          headers.add(line);
        } else if (!textDone && type == ArmorType.signedMessage) {
          if (!splitPattern.hasMatch(line)) {
            textLines.add(line.trimRight().replaceAll(RegExp(r'^- '), ''));
          } else {
            textDone = true;
            if (textLines.isNotEmpty) {
              /// Remove first empty line (not included in the message digest)
              textLines.removeAt(0);
            }
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

    final text = textLines.join('\r\n');
    final data = base64.decode(dataLines.join().trim());

    if ((checksum != _crc24Checksum(data)) &&
        (checksum.isNotEmpty || Config.checksumRequired)) {
      throw AssertionError('Ascii armor integrity check failed');
    }

    return Armor(
      type ?? ArmorType.multipartSection,
      data,
      headers: headers,
      text: text,
    );
  }

  /// Assert armor type
  Armor assertType(ArmorType type) {
    if (type != this.type) {
      throw AssertionError('Armored text not of ${type.name} type.');
    }
    return this;
  }

  /// Armor an OpenPGP binary packet block
  static String encode(
    final ArmorType type,
    final Uint8List data, {
    final String text = '',
    final Iterable<String> hashAlgos = const [],
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
        final hashHeaders = hashAlgos.map((hash) => 'Hash: $hash').join('\n');
        result = [
          '$signedMessageBegin$endOfLine',
          hashHeaders.isNotEmpty ? '$hashHeaders\n\n' : '',
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
    }
    return result.join();
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
    return base64.encode(data).chunk(base64Chunk).join('\n');
  }

  static String _crc24Checksum(final Uint8List bytes) {
    var crc = 0xb704ce;
    for (final byte in bytes) {
      crc ^= byte << 16;
      for (var i = 0; i < 8; i++) {
        crc <<= 1;
        if ((crc & 0x1000000) != 0) {
          crc ^= 0x1864cfb;
        }
      }
    }
    return base64.encode((crc & 0xffffff).pack32().sublist(1));
  }
}
