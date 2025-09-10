/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/extensions.dart';

/// Armor types enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum ArmorType {
  signedMessage,
  message,
  publicKey,
  privateKey,
  signature;

  static const _beginPattern = r'^-----BEGIN PGP (SIGNED MESSAGE|MESSAGE|'
      r'PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$';

  factory ArmorType.fromBegin(final String text) {
    final matches = RegExp(_beginPattern).allMatches(text);
    if (matches.isEmpty) {
      throw ArgumentError('Unknown ASCII armor type');
    }
    final match = matches.elementAt(0)[0]!;
    if (r'SIGNED MESSAGE'.hasMatch(match)) {
      return signedMessage;
    } else if (r'MESSAGE'.hasMatch(match)) {
      return message;
    } else if (r'PUBLIC KEY BLOCK'.hasMatch(match)) {
      return publicKey;
    } else if (r'PRIVATE KEY BLOCK'.hasMatch(match)) {
      return privateKey;
    } else if (r'SIGNATURE'.hasMatch(match)) {
      return signature;
    }
    return message;
  }
}
