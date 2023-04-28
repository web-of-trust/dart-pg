import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/crypto/math/byte_ext.dart';
import 'package:dart_pg/src/enum/hash_algorithm.dart';
import 'package:dart_pg/src/enum/s2k_type.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/packet/key/s2k.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/sym_encrypted_session_key.dart';
import 'package:test/test.dart';

import '../data/s2k_data.dart';

void main() {
  group('s2k', () {
    test('mode-0-password-1234 test', () async {
      const passphrase = '1234';
      final salt = Uint8List.fromList([]);

      final packets = PacketList.packetDecode(base64.decode(mode0Password1234));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.simple);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), '7110eda4d09e062aa5e4a390b0a572ac0d2c0220f352b0d292b65164c2a67301');
    });

    test('mode-1-password-123456 test', () async {
      const passphrase = '123456';
      final salt = Uint8List.fromList([0xa8, 0x42, 0xa7, 0xa9, 0x59, 0xfa, 0x42, 0x2a]);

      final packets = PacketList.packetDecode(base64.decode(mode1Password123456));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.salted);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), '8b79077ca448f6fb3d3ad2a264d3b938d357c9fb3e41219fd962df960a9afa08');
    });

    test('mode-1-password-foobar test', () async {
      const passphrase = 'foobar';
      final salt = Uint8List.fromList([0xbc, 0x95, 0x58, 0x45, 0x81, 0x3c, 0x7c, 0x37]);

      final packets = PacketList.packetDecode(base64.decode(mode1PasswordFoobar));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.salted);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), 'b7d48aae9b943b22a4d390083e8460b5edfa118fe1688bf0c473b8094d1a8d10');
    });

    test('mode-3-password-qwerty test', () async {
      const itCount = 241;
      const passphrase = 'qwerty';
      final salt = Uint8List.fromList([0x78, 0x45, 0xf0, 0x5b, 0x55, 0xf7, 0xb4, 0x9e]);

      final packets = PacketList.packetDecode(base64.decode(mode3PasswordQwerty));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.iterated);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.itCount, itCount);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash, itCount: skesk.s2k.itCount);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), '575ad156187a3f8cec11108309236eb499f1e682f0d1afadfac4ecf97613108a');
    });

    test('mode-3-password-9876 test', () async {
      const itCount = 43;
      const passphrase = '9876';
      final salt = Uint8List.fromList([0xb9, 0x67, 0xea, 0x96, 0x53, 0xdb, 0x6a, 0xc8]);

      final packets = PacketList.packetDecode(base64.decode(mode3Password9876));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.iterated);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.itCount, itCount);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash, itCount: skesk.s2k.itCount);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), '736c226b8c64e4e6d0325c6c552ef7c0738f98f48fed65fd8c93265103efa23a');
    });

    test('mode-3-aes192-password-123 test', () async {
      const itCount = 238;
      const passphrase = '123';
      final salt = Uint8List.fromList([0x8f, 0x81, 0x74, 0xc5, 0xd9, 0x61, 0xc7, 0x79]);

      final packets = PacketList.packetDecode(base64.decode(mode3Aes192Password123));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.iterated);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.itCount, itCount);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes192);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash, itCount: skesk.s2k.itCount);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), '915e96fc694e7f90a6850b740125ea005199c725f3bd27e3');
    });

    test('mode-3-twofish-password-13-times-0123456789 test', () async {
      const itCount = 238;
      const passphrase =
          '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789';
      final salt = Uint8List.fromList([0x51, 0xed, 0xfc, 0x15, 0x45, 0x40, 0x65, 0xac]);

      final packets = PacketList.packetDecode(base64.decode(mode3TwofishPassword13Times0123456789));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.iterated);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.itCount, itCount);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.twofish);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash, itCount: skesk.s2k.itCount);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), 'ea264fada5a859c40d88a159b344ecf1f51ff327fdb3c558b0a7dc299777173e');
    });

    test('mode-3-aes128-password-13-times-0123456789 test', () async {
      const itCount = 238;
      const passphrase =
          '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789';
      final salt = Uint8List.fromList([0x06, 0xe4, 0x61, 0x5c, 0xa4, 0x48, 0xf9, 0xdd]);

      final packets = PacketList.packetDecode(base64.decode(mode3Aes128Password13Times0123456789));
      final skesk = packets[0] as SymEncryptedSessionKeyPacket;
      expect(skesk.s2k.type, S2kType.iterated);
      expect(skesk.s2k.hash, HashAlgorithm.sha1);
      expect(skesk.s2k.itCount, itCount);
      expect(skesk.s2k.salt, equals(salt));
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);

      final s2k = S2K(salt, type: skesk.s2k.type, hash: skesk.s2k.hash, itCount: skesk.s2k.itCount);
      final key = await s2k.produceKey(passphrase, (skesk.symmetric.keySize + 7) >> 3);
      expect(key.toHexadecimal(), 'f3d0ce52ed6143637443e3399437fd0f');
    });
  });
}
