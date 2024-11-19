/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// A list of packet types and numeric tags associated with them.
/// See https://www.rfc-editor.org/rfc/rfc9580#section-5
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum PacketType {
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
  aeadEncryptedData(20),
  padding(21);

  final int value;

  const PacketType(this.value);
}