// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum SignatureSubpacketType {
  signatureCreationTime(2),
  signatureExpirationTime(3),
  exportableCertification(4),
  trustSignature(5),
  regularExpression(6),
  revocable(7),
  keyExpirationTime(9),
  placeholderBackwardCompatibility(10),
  preferredSymmetricAlgorithms(11),
  revocationKey(12),
  issuerKeyID(16),
  notationData(20),
  preferredHashAlgorithms(21),
  preferredCompressionAlgorithms(22),
  keyServerPreferences(23),
  preferredKeyServer(24),
  primaryUserID(25),
  policyURI(26),
  keyFlags(27),
  signerUserID(28),
  revocationReason(29),
  features(30),
  signatureTarget(31),
  embeddedSignature(32),
  issuerFingerprint(33),
  preferredAEADAlgorithms(34),
  intendedRecipientFingerprint(35),
  attestedCertifications(37);

  final int value;

  const SignatureSubpacketType(this.value);
}
