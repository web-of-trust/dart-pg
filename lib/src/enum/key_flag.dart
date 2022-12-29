// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum KeyFlag {
  certifyKeys(1),
  signData(2),
  encryptCommunication(4),
  encryptStorage(8),
  splitPrivateKey(16),
  authentication(32),
  sharedPrivateKey(128);

  final int value;

  const KeyFlag(this.value);
}
