/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// S2k usage
/// Indicating whether and how the secret key material is protected by a passphrase
/// See https://www.rfc-editor.org/rfc/rfc9580#section-3.7.2
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum S2kUsage {
  none(0),
  aeadProtect(253),
  cfb(254),
  malleableCfb(255);

  final int value;

  const S2kUsage(this.value);
}
