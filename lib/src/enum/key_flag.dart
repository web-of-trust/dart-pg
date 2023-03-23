// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Key flag
enum KeyFlag {
  /// 0x01 - This key may be used to certify other keys.
  certifyKeys(1),

  /// 0x02 - This key may be used to sign data.
  signData(2),

  /// 0x04 - This key may be used to encrypt communications.
  encryptCommunication(4),

  /// 0x08 - This key may be used to encrypt storage.
  encryptStorage(8),

  /// 0x10 - The private component of this key may have been split by a secret-sharing mechanism.
  splitPrivateKey(16),

  /// 0x20 - This key may be used for authentication.
  authentication(32),

  /// 0x80 - The private component of this key may be in the possession of more than one person.
  sharedPrivateKey(128);

  final int value;

  const KeyFlag(this.value);
}
