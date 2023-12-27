import 'dart:typed_data';

import 'package:dart_pg/src/crypto/aead/eax.dart';
import 'package:dart_pg/src/crypto/aead/gcm.dart';
import 'package:dart_pg/src/crypto/aead/ocb.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:test/test.dart';

void main() {
  group('eax tests', () {
    final testVectors = [
      {
        'name': 'Test Case 1',
        'msg': '',
        'key': '233952dee4d5ed5f9b9c6d6ff80ff478',
        'nonce': '62ec67f9c3a4a407fcb2a8c49031a8b3',
        'header': '6bfb914fd07eae6b',
        'cipher': 'e037830e8389f27b025a2d6527e79d01',
      },
      {
        'name': 'Test Case 2',
        'msg': 'f7fb',
        'key': '91945d3f4dcbee0bf45ef52255f095a4',
        'nonce': 'becaf043b0a23d843194ba972c66debd',
        'header': 'fa3bfd4806eb53fa',
        'cipher': '19dd5c4c9331049d0bdab0277408f67967e5',
      },
      {
        'name': 'Test Case 3',
        'msg': '1a47cb4933',
        'key': '01f74ad64077f2e704c0f60ada3dd523',
        'nonce': '70c3db4f0d26368400a10ed05d2bff5e',
        'header': '234a3463c1264ac6',
        'cipher': 'd851d5bae03a59f238a23e39199dc9266626c40f80',
      },
      {
        'name': 'Test Case 4',
        'msg': '481c9e39b1',
        'key': 'd07cf6cbb7f313bdde66b727afd3c5e8',
        'nonce': '8408dfff3c1a2b1292dc199e46b7d617',
        'header': '33cce2eabff5a79d',
        'cipher': '632a9d131ad4c168a4225d8e1ff755939974a7bede',
      },
      {
        'name': 'Test Case 5',
        'msg': '40d0c07da5e4',
        'key': '35b6d0580005bbc12b0587124557d2c2',
        'nonce': 'fdb6b06676eedc5c61d74276e1f8e816',
        'header': 'aeb96eaebe2970e9',
        'cipher': '071dfe16c675cb0677e536f73afe6a14b74ee49844dd',
      },
      {
        'name': 'Test Case 6',
        'msg': '4de3b35c3fc039245bd1fb7d',
        'key': 'bd8e6e11475e60b268784c38c62feb22',
        'nonce': '6eac5c93072d8e8513f750935e46da1b',
        'header': 'd4482d1ca78dce0f',
        'cipher': '835bb4f15d743e350e728414abb8644fd6ccb86947c5e10590210a4f',
      },
      {
        'name': 'Test Case 7',
        'msg': '8b0a79306c9ce7ed99dae4f87f8dd61636',
        'key': '7c77d6e813bed5ac98baa417477a2e7d',
        'nonce': '1a8c98dcd73d38393b2bf1569deefc19',
        'header': '65d2017990d62528',
        'cipher': '02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2',
      },
      {
        'name': 'Test Case 8',
        'msg': '1bda122bce8a8dbaf1877d962b8592dd2d56',
        'key': '5fff20cafab119ca2fc73549e20f5b0d',
        'nonce': 'dde59b97d722156d4d9aff2bc7559826',
        'header': '54b9f04e6a09189a',
        'cipher': '2ec47b2c4954a489afc7ba4897edcdae8cc33b60450599bd02c96382902aef7f832a',
      },
      {
        'name': 'Test Case 9',
        'msg': '6cf36720872b8513f6eab1a8a44438d5ef11',
        'key': 'a4a4782bcffd3ec5e7ef6d8c34a56123',
        'nonce': 'b781fcf2f75fa5a8de97a9ca48e522ec',
        'header': '899a175897561d7e',
        'cipher': '0de18fd0fdd91e7af19f1d8ee8733938b1e8e7f6d2231618102fdb7fe55ff1991700',
      },
      {
        'name': 'Test Case 10',
        'msg': 'ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7',
        'key': '8395fcf1e95bebd697bd010bc766aac3',
        'nonce': '22e7add93cfc6393c57ec0b3c17d6b44',
        'header': '126735fcc320d25a',
        'cipher': 'cb8920f87a6c75cff39627b56e3ed197c552d295a7cfc46afc253b4652b1af3795b124ab6e',
      },
    ];
    for (var map in testVectors) {
      test(map['name'], () {
        final msg = map['msg']!.hexToBytes();
        final key = map['key']!.hexToBytes();
        final nonce = map['nonce']!.hexToBytes();
        final header = map['header']!.hexToBytes();
        final cipher = map['cipher']!.hexToBytes();

        final eax = Eax(key, SymmetricAlgorithm.aes128);

        /// encryption test
        var ct = eax.encrypt(msg, nonce, header);
        expect(ct, equals(cipher), reason: 'encryption test $map["name"] did not match output');

        /// decryption test with verification
        var pt = eax.decrypt(cipher, nonce, header);
        expect(pt, equals(msg), reason: 'decryption test $map["name"] did not match output');

        /// testing without additional data
        ct = eax.encrypt(msg, nonce, Uint8List(0));
        pt = eax.decrypt(ct, nonce, Uint8List(0));
        expect(pt, equals(msg), reason: 'test $map["name"] did not match output');

        /// testing with multiple additional data
        ct = eax.encrypt(msg, nonce, Uint8List.fromList([...header, ...header, ...header]));
        pt = eax.decrypt(ct, nonce, Uint8List.fromList([...header, ...header, ...header]));
        expect(pt, equals(msg), reason: 'test $map["name"] did not match output');
      });
    }
  });

  group('ocb tests', () {
    final key = '000102030405060708090a0b0c0d0e0f'.hexToBytes();
    final testVectors = [
      {
        'name': 'Test Case 1',
        'N': 'bbaa99887766554433221100',
        'A': '',
        'P': '',
        'C': '785407bfffc8ad9edcc5520ac9111ee6',
      },
      {
        'name': 'Test Case 2',
        'N': 'bbaa99887766554433221101',
        'A': '0001020304050607',
        'P': '0001020304050607',
        'C': '6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009',
      },
      {
        'name': 'Test Case 3',
        'N': 'bbaa99887766554433221102',
        'A': '0001020304050607',
        'P': '',
        'C': '81017f8203f081277152fade694a0a00',
      },
      {
        'name': 'Test Case 4',
        'N': 'bbaa99887766554433221103',
        'A': '',
        'P': '0001020304050607',
        'C': '45dd69f8f5aae72414054cd1f35d82760b2cd00d2f99bfa9',
      },
      {
        'name': 'Test Case 5',
        'N': 'bbaa99887766554433221104',
        'A': '000102030405060708090a0b0c0d0e0f',
        'P': '000102030405060708090a0b0c0d0e0f',
        'C': '571d535b60b277188be5147170a9a22c3ad7a4ff3835b8c5701c1ccec8fc3358',
      },
      {
        'name': 'Test Case 6',
        'N': 'bbaa99887766554433221105',
        'A': '000102030405060708090a0b0c0d0e0f',
        'P': '',
        'C': '8cf761b6902ef764462ad86498ca6b97',
      },
      {
        'name': 'Test Case 7',
        'N': 'bbaa99887766554433221106',
        'A': '',
        'P': '000102030405060708090a0b0c0d0e0f',
        'C': '5ce88ec2e0692706a915c00aeb8b2396f40e1c743f52436bdf06d8fa1eca343d',
      },
      {
        'name': 'Test Case 8',
        'N': 'bbaa99887766554433221107',
        'A': '000102030405060708090a0b0c0d0e0f1011121314151617',
        'P': '000102030405060708090a0b0c0d0e0f1011121314151617',
        'C': '1ca2207308c87c010756104d8840ce1952f09673a448a122c92c62241051f57356d7f3c90bb0e07f',
      },
      {
        'name': 'Test Case 9',
        'N': 'bbaa99887766554433221108',
        'A': '000102030405060708090a0b0c0d0e0f1011121314151617',
        'P': '',
        'C': '6dc225a071fc1b9f7c69f93b0f1e10de',
      },
      {
        'name': 'Test Case 10',
        'N': 'bbaa99887766554433221109',
        'A': '',
        'P': '000102030405060708090a0b0c0d0e0f1011121314151617',
        'C': '221bd0de7fa6fe993eccd769460a0af2d6cded0c395b1c3ce725f32494b9f914d85c0b1eb38357ff',
      },
      {
        'name': 'Test Case 11',
        'N': 'bbaa9988776655443322110a',
        'A': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'P': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'C': 'bd6f6c496201c69296c11efd138a467abd3c707924b964deaffc40319af5a48540fbba186c5553c68ad9f592a79a4240',
      },
      {
        'name': 'Test Case 12',
        'N': 'bbaa9988776655443322110b',
        'A': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'P': '',
        'C': 'fe80690bee8a485d11f32965bc9d2a32',
      },
      {
        'name': 'Test Case 13',
        'N': 'bbaa9988776655443322110c',
        'A': '',
        'P': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'C': '2942bfc773bda23cabc6acfd9bfd5835bd300f0973792ef46040c53f1432bcdfb5e1dde3bc18a5f840b52e653444d5df',
      },
      {
        'name': 'Test Case 4',
        'N': 'bbaa9988776655443322110d',
        'A': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
        'P': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
        'C':
            'd5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7aed07ba06a4a69483a7035490c5769e60',
      },
      {
        'name': 'Test Case 15',
        'N': 'bbaa9988776655443322110e',
        'A': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
        'P': '',
        'C': 'c5cd9d1850c141e358649994ee701b68',
      },
      {
        'name': 'Test Case 6',
        'N': 'bbaa9988776655443322110f',
        'A': '',
        'P': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
        'C':
            '4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e479ad363ac366b95a98ca5f3000b1479',
      },
    ];
    for (var map in testVectors) {
      test(map['name'], () {
        final msg = map['P']!.hexToBytes();
        final nonce = map['N']!.hexToBytes();
        final header = map['A']!.hexToBytes();
        final cipher = map['C']!.hexToBytes();

        final ocb = Ocb(key, SymmetricAlgorithm.aes128);

        /// encryption test
        var ct = ocb.encrypt(msg, nonce, header);
        expect(ct, equals(cipher), reason: 'encryption test $map["name"] did not match output');

        /// decryption test with verification
        var pt = ocb.decrypt(cipher, nonce, header);
        expect(pt, equals(msg), reason: 'decryption test $map["name"] did not match output');

        /// testing without additional data
        ct = ocb.encrypt(msg, nonce, Uint8List(0));
        pt = ocb.decrypt(ct, nonce, Uint8List(0));
        expect(pt, equals(msg), reason: 'test $map["name"] did not match output');

        /// testing with multiple additional data
        ct = ocb.encrypt(msg, nonce, Uint8List.fromList([...header, ...header, ...header]));
        pt = ocb.decrypt(ct, nonce, Uint8List.fromList([...header, ...header, ...header]));
        expect(pt, equals(msg), reason: 'test $map["name"] did not match output');
      });
    }
  });

  group('gcm tests', () {
    final testVectors = [
      {
        'name': 'Test Case 1',
        'key': '00000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '',
        'output': '',
        'mac': '58e2fccefa7e3061367f1d57a4e7455a',
      },
      {
        'name': 'Test Case 2',
        'key': '00000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '00000000000000000000000000000000',
        'output': '0388dace60b6a392f328c2b971b2fe78',
        'mac': 'ab6e47d42cec13bdf53a67b21257bddf',
      },
      {
        'name': 'Test Case 3',
        'key': 'feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': '',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'output':
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
        'mac': '4d5c2af327cd64a62cf35abd2ba6fab4',
      },
      {
        'name': 'Test Case 4',
        'key': 'feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
        'mac': '5bc94fbc3221a5db94fae95ae7121a47',
      },
      {
        'name': 'Test Case 5',
        'key': 'feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbad',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598',
        'mac': '3612d2e79e3b0785561be14aaca2fccb',
      },
      {
        'name': 'Test Case 6',
        'key': 'feffe9928665731c6d6a8f9467308308',
        'iv':
            '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5',
        'mac': '619cc5aefffe0bfa462af43c1699d050',
      },
      {
        'name': 'Test Case 7',
        'key': '000000000000000000000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '',
        'output': '',
        'mac': 'cd33b28ac773f74ba00ed1f312572435',
      },
      {
        'name': 'Test Case 8',
        'key': '000000000000000000000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '00000000000000000000000000000000',
        'output': '98e7247c07f0fe411c267e4384b0f600',
        'mac': '2ff58d80033927ab8ef4d4587514f0fb',
      },
      {
        'name': 'Test Case 9',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': '',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'output':
            '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256',
        'mac': '9924a7c8587336bfb118024db8674a14',
      },
      {
        'name': 'Test Case 10',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710',
        'mac': '2519498e80f1478f37ba55bd6d27618c',
      },
      {
        'name': 'Test Case 11',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
        'iv': 'cafebabefacedbad',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7',
        'mac': '65dcc57fcf623a24094fcca40d3533f8',
      },
      {
        'name': 'Test Case 12',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
        'iv':
            '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            'd27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b',
        'mac': 'dcf566ff291c25bbb8568fc3d376a6d9',
      },
      {
        'name': 'Test Case 13',
        'key': '0000000000000000000000000000000000000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '',
        'output': '',
        'mac': '530f8afbc74536b9a963b4f1c4cb738b',
      },
      {
        'name': 'Test Case 14',
        'key': '0000000000000000000000000000000000000000000000000000000000000000',
        'iv': '000000000000000000000000',
        'aad': '',
        'input': '00000000000000000000000000000000',
        'output': 'cea7403d4d606b6e074ec5d3baf39d18',
        'mac': 'd0d1c8a799996bf0265b98b5d48ab919',
      },
      {
        'name': 'Test Case 15',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': '',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'output':
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
        'mac': 'b094dac5d93471bdec1a502270e3cc6c',
      },
      {
        'name': 'Test Case 16',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbaddecaf888',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
        'mac': '76fc6ece0f4e1768cddf8853bb2d551b',
      },
      {
        'name': 'Test Case 17',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'iv': 'cafebabefacedbad',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            'c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f',
        'mac': '3a337dbf46a792c45e454913fe2ea8f2',
      },
      {
        'name': 'Test Case 18',
        'key': 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'iv':
            '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        'aad': 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        'input':
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'output':
            '5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f',
        'mac': 'a44a8266ee1c8eb0c8b5d4cf5ae9f19a',
      },
    ];

    for (var map in testVectors) {
      test(map['name'], () {
        final key = map['key']!.hexToBytes();
        final iv = map['iv']!.hexToBytes();
        final aad = map['aad']!.hexToBytes();
        final input = map['input']!.hexToBytes();
        final output = map['output']!.hexToBytes();
        final mac = map['mac']!.hexToBytes();

        final gcm = Gcm(
          key,
          SymmetricAlgorithm.aes128,
        );

        /// encryption test
        var ct = gcm.encrypt(input, iv, aad);
        expect(ct, equals(Uint8List.fromList([...output, ...mac])),
            reason: 'encryption test $map["name"] did not match output');

        /// decryption test with verification
        var pt = gcm.decrypt(Uint8List.fromList([...output, ...mac]), iv, aad);
        expect(pt, equals(input), reason: 'decryption test $map["name"] did not match output');

        /// testing without additional data
        ct = gcm.encrypt(input, iv, Uint8List(0));
        pt = gcm.decrypt(ct, iv, Uint8List(0));
        expect(pt, equals(input), reason: 'test $map["name"] did not match output');

        /// testing with multiple additional data
        ct = gcm.encrypt(input, iv, Uint8List.fromList([...aad, ...aad, ...aad]));
        pt = gcm.decrypt(ct, iv, Uint8List.fromList([...aad, ...aad, ...aad]));
        expect(pt, equals(input), reason: 'test $map["name"] did not match output');
      });
    }
  });
}
