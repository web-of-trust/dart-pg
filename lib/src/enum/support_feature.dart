// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Support Feature
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum SupportFeature {
  /// 0x01 - Modification Detection (packets 18 and 19)
  modificationDetection(1),

  /// 0x02 - AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key Encrypted Session Key Packets (packet 3)
  aeadEncryptedData(2),

  /// 0x04 - Version 5 Public-Key Packet format and corresponding new fingerprint format
  version5PublicKey(4);

  final int value;

  const SupportFeature(this.value);
}
