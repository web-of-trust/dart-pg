import 'dart:typed_data';

import 'package:dart_pg/src/crypto/asymmetric/elgamal.dart';
import 'package:dart_pg/src/crypto/signer/dsa.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:pointycastle/api.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  final faker = Faker();

  group('ElGamal encryption tests', () {
    test('Enc 512 Test', () {
      final p512 = BigInt.parse(
          '9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b',
          radix: 16);
      final g512 = BigInt.parse(
          '153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc',
          radix: 16);

      _elGamalEncryptionTest(p512, g512, 512);
    });

    test('Enc 768 Test', (() {
      final p768 = BigInt.parse(
          '8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f',
          radix: 16);
      final g768 = BigInt.parse(
          '7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1',
          radix: 16);

      _elGamalEncryptionTest(p768, g768, 768);
    }));

    test('Enc 1024 Test', (() {
      final p1024 = BigInt.parse(
          'a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7',
          radix: 16);
      final g1024 = BigInt.parse(
          '1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf',
          radix: 16);

      _elGamalEncryptionTest(p1024, g1024, 1024);
    }));

    test('Diffie Hellman key agreement test', (() {
      final prime = BigInt.parse(
          'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff',
          radix: 16);
      final generator = BigInt.two;
      final alicePrivate = BigInt.parse(
          '22606eda7960458bc9d65f46dd96f114f9a004f0493c1f262139d2c8063b733162e876182ca3bf063ab1a167abdb7f03e0a225a6205660439f6ce46d252069ff',
          radix: 16);
      final bobPrivate = BigInt.parse(
          '6e3efa13a96025d63e4b0d88a09b3a46ddfe9dd3bc9d16554898c02b4ac181f0ceb4e818664b12f02c71a07215c400f988352a4779f3e88836f7c3d3b3c739de',
          radix: 16);

      final alicePublic = generator.modPow(alicePrivate, prime);
      final bobPublic = generator.modPow(bobPrivate, prime);

      final aliceShared = bobPublic.modPow(alicePrivate, prime);
      final bobShared = alicePublic.modPow(bobPrivate, prime);
      expect(aliceShared, bobShared, reason: 'Failed asserting that Alice and Bob share the same BigInteger.');
    }));
  });

  group('DSA signer tests', (() {
    final pValue = BigInt.parse(
        'e0a67598cd1b763bc98c8abb333e5dda0cd3aa0e5e1fb5ba8a7b4eabc10ba338fae06dd4b90fda70d7cf0cb0c638be3341bec0af8a7330a3307ded2299a0ee606df035177a239c34a912c202aa5f83b9c4a7cf0235b5316bfc6efb9a248411258b30b839af172440f32563056cb67a861158ddd90e6a894c72a5bbef9e286c6b',
        radix: 16);
    final qValue = BigInt.parse('e950511eab424b9a19a2aeb4e159b7844c589c4f', radix: 16);
    final gValue = BigInt.parse(
        'd29d5121b0423c2769ab21843e5a3240ff19cacc792264e3bb6be4f78edd1b15c4dff7f1d905431f0ab16790e1f773b5ce01c804e509066a9919f5195f4abc58189fd9ff987389cb5bedf21b4dab4f8b76a055ffe2770988fe2ec2de11ad92219f0b351869ac24da3d7ba87011a701ce8ee7bfe49486ed4527b7186ca4610a75',
        radix: 16);
    final xValue = BigInt.parse('d0ec4e50bb290a42e9e355c73d8809345de2e139', radix: 16);

    final privateKey = DSAPrivateKey(xValue, pValue, qValue, gValue);
    final publicKey = privateKey.publicKey;

    final message = faker.randomGenerator.string(100).stringToBytes();

    test('With sha1 test', (() {
      final signer = DSASigner(Digest('SHA-1'));

      signer.init(true, PrivateKeyParameter<DSAPrivateKey>(privateKey));
      final signature = signer.generateSignature(message);
      signer.init(false, PublicKeyParameter<DSAPublicKey>(publicKey));
      expect(signer.verifySignature(message, signature), true);
    }));

    test('With sha256 test', (() {
      final signer = DSASigner(Digest('SHA-256'));

      signer.init(true, PrivateKeyParameter<DSAPrivateKey>(privateKey));
      final signature = signer.generateSignature(message);
      signer.init(false, PublicKeyParameter<DSAPublicKey>(publicKey));
      expect(signer.verifySignature(message, signature), true);
    }));
  }));
}

void _elGamalEncryptionTest(BigInt p, BigInt g, int size) {
  final x = _dhCalculatePrivateKey(p);
  final privateKey = ElGamalPrivateKey(x, p, g);
  final publicKey = privateKey.publicKey;

  final engine = ElGamalEngine();
  engine.init(true, PublicKeyParameter<ElGamalPublicKey>(publicKey));
  expect(engine.outputBlockSize, size ~/ 4, reason: "$size outputBlockSize on encryption failed.");

  final message = "5468697320697320612074657374".hexToBytes();
  final plainText = message;
  final cipherText = Uint8List(engine.outputBlockSize);
  engine.processBlock(plainText, 0, plainText.length, cipherText, 0);

  engine.init(false, PrivateKeyParameter<ElGamalPrivateKey>(privateKey));
  engine.processBlock(cipherText, 0, cipherText.length, plainText, 0);

  expect(engine.outputBlockSize, (size ~/ 8) - 1, reason: "$size outputBlockSize on decryption failed.");
  expect(message, equals(plainText), reason: '$size bit test failed');
}

BigInt _dhCalculatePrivateKey(BigInt p) {
  final random = Helper.secureRandom();
  final min = BigInt.two;
  final max = p - BigInt.two;
  final minWeight = max.bitLength >> 2;
  var x = random.nextBigInteger(max.bitLength);
  while ((x.compareTo(min) < 0) || (x.compareTo(max) > 0) || (_getNafWeight(x) < minWeight)) {
    x = random.nextBigInteger(max.bitLength);
  }
  return x;
}

int _getNafWeight(BigInt k) {
  if (k.sign == 0) {
    return 0;
  }
  final k3 = (k << 1) + k;
  final diff = k3 ^ k;
  return diff.bitLength;
}
