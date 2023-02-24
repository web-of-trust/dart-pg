// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// A list of packet types and numeric tags associated with them.
enum PacketTag {
  publicKeyEncryptedSessionKey(1),
  signature(2),
  symEncryptedSessionKey(3),
  onePassSignature(4),
  secretKey(5),
  publicKey(6),
  secretSubkey(7),
  compressedData(8),
  symEncryptedData(9),
  marker(10),
  literalData(11),
  trust(12),
  userID(13),
  publicSubkey(14),
  userAttribute(17),
  symEncryptedIntegrityProtectedData(18),
  modificationDetectionCode(19);

  final int value;

  const PacketTag(this.value);
}
