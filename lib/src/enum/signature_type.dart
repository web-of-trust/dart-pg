/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

export 'aead_algorithm.dart';
export 'compression_algorithm.dart';
export 'key_flag.dart';
export 'key_version.dart';
export 'literal_format.dart';
export 'support_feature.dart';
export 'symmetric_algorithm.dart';
export 'hash_algorithm.dart';
export 'key_algorithm.dart';
export 'signature_subpacket_type.dart';

///Signature types enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum SignatureType {
  /// Signature of a binary document.
  binary(0),

  /// Signature of a canonical text document.
  ///
  /// Canonicalyzing the document by converting line endings.
  text(1),

  /// Standalone signature.
  ///
  /// This signature is a signature of only its own subpacket contents.
  /// It is calculated identically to a signature over a zero-lengh binary document.
  /// Note that it doesn't make sense to have a V3 standalone signature.
  standalone(2),

  /// Generic certification of a User ID and Public-Key packet.
  ///
  /// The issuer of this certification does not make any particular
  /// assertion as to how well the certifier has checked that the owner
  /// of the key is in fact the person described by the User ID.
  certGeneric(16),

  /// Persona certification of a User ID and Public-Key packet.
  ///
  /// The issuer of this certification has not done any verification of
  /// the claim that the owner of this key is the User ID specified.
  certPersona(17),

  /// Casual certification of a User ID and Public-Key packet.
  ///
  /// The issuer of this certification has done some casual verification of the claim of identity.
  certCasual(18),

  /// Positive certification of a User ID and Public-Key packet.
  ///
  /// The issuer of this certification has done substantial verification of the claim of identity.
  /// Most OpenPGP implementations make their "key signatures" as 0x10 certifications.
  /// Some implementations can issue 0x11-0x13 certifications, but few differentiate between the types.
  certPositive(19),

  /// Certification revocation signature.
  ///
  /// This signature revokes an earlier User ID certification signature
  /// (signature class 0x10 through 0x13) or direct-key signature (0x1F).
  /// It should be issued by the same key that issued the revoked signature or an authorized revocation key.
  /// The signature is computed over the same data as the certificate that it
  /// revokes, and should have a later creation date than that certificate.
  certRevocation(48),

  /// Subkey binding signature.
  ///
  /// This signature is a statement by the top-level signing key that indicates that it owns the subkey.
  /// This signature is calculated directly on the primary key and subkey,
  /// and not on any User ID or other packets.
  /// A signature that binds a signing subkey MUST have an Embedded Signature subpacket in this binding signature
  /// that contains a 0x19 signature made by the signing subkey on the primary key and subkey.
  subkeyBinding(24),

  /// Primary Key Binding Signature
  ///
  /// This signature is a statement by a signing subkey, indicating
  /// that it is owned by the primary key and subkey.
  /// This signature is calculated the same way as a 0x18 signature: directly on the
  /// primary key and subkey, and not on any User ID or other packets.
  ///
  /// When a signature is made over a key, the hash data starts with the octet 0x99,
  /// followed by a two-octet length of the key, and then body  of the key packet.
  /// (Note that this is an old-style packet header for a key packet with two-octet length.)
  /// A subkey binding signature (type 0x18) or primary key binding signature (type 0x19) then hashes
  /// the subkey using the same format as the main key (also using 0x99 as the first octet).
  keyBinding(25),

  /// Signature directly on a key
  ///
  /// This signature is calculated directly on a key.
  /// It binds the information in the Signature subpackets to the key,
  /// and is appropriate to be used for subpackets that provide information
  /// about the key, such as the Revocation Key subpacket.
  /// It is also appropriate for statements that non-self certifiers want to make
  /// about the key itself, rather than the binding between a key and a name.
  directKey(31),

  /// Key revocation signature
  ///
  /// The signature is calculated directly on the key being revoked.
  /// A revoked key is not to be used.
  /// Only revocation signatures by the key being revoked, or by an authorized revocation key,
  /// should be considered valid revocation signatures.
  keyRevocation(32),

  /// Subkey revocation signature
  ///
  /// The signature is calculated directly on the subkey being revoked.
  /// A revoked subkey is not to be used.  Only revocation signatures
  /// by the top-level signature key that is bound to this subkey, or
  /// by an authorized revocation key, should be considered valid revocation signatures.
  /// Key revocation signatures (types 0x20 and 0x28) hash only the key being revoked.
  subkeyRevocation(40),

  /// Timestamp signature.
  ///
  /// This signature is only meaningful for the timestamp contained in it.
  timestamp(64),

  /// Third-Party Confirmation signature.
  ///
  /// This signature is a signature over some other OpenPGP Signature packet(s).
  /// It is analogous to a notary seal on the signed data.
  /// A third-party signature SHOULD include Signature Target
  /// subpacket(s) to give easy identification.  Note that we really do
  /// mean SHOULD.  There are plausible uses for this (such as a blind
  /// party that only sees the signature, not the key or source
  /// document) that cannot include a target subpacket.
  thirdParty(80);

  final int value;

  const SignatureType(this.value);
}
