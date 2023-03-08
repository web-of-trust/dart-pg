import 'dart:typed_data';

import 'package:dart_pg/src/crypto/asymmetric/elgamal.dart';
import 'package:dart_pg/src/crypto/signer/dsa.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:pointycastle/api.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('ElGamal', () {
    test('encryption test', () {
      final prime = BigInt.parse(
          '21842708581829896181355246474716153471799584702398145343781873612858268458790012658568509171208714431649208343296936349116172973580334664598762798393358559705621580042818388996849377434152861440023221391670968030831872591041152546055355390395164610169584848575897862985569697158568543863240507089993891556886557196474202323417190832644888994692005921518845406236886593318056471289387692729870131076001447553511077011608675277948641532603949929873743962633410696917376288603162134431896218895079026006444970460740888015606154190820808415464316451512185142037759825776982215354150775475714608377003555330213945294287583');
      final generator = BigInt.from(5);
      final publicExponent = BigInt.parse(
          '15590699273124096367845758349645226104138190024888407784287357837260359983637081328343487075505090749437978508505177973032496352672432943366064714761944186683268687737839702679962914617907849880272896027951360632795432278109768129193340345955504697749295122222309114553683024697759013607172925522796547740584824687858596370069179394322422986612767141828757141197590339291313205573787292371971283021600112532974909997630543606784003003770779526568284167901082742375947463384656907527559426381569970468966330515531538944216482677858434221351520007191681768077185259988739987157075690073689280587056931667283700771424191');
      final secretExponent = BigInt.parse(
          '1446296390097566101617671091884237397227201126182287254457502825594360365391017793839243843109598388819');

      final publicKey = ElGamalPublicKey(publicExponent, prime, generator);
      final privateKey = ElGamalPrivateKey(secretExponent, prime, generator);

      final engine = ElGamalEngine();
      engine.init(true, PublicKeyParameter<ElGamalPublicKey>(publicKey));
      expect(engine.outputBlockSize, 2048 ~/ 4, reason: "2048 outputBlockSize on encryption failed.");

      final message = faker.randomGenerator.string(100).stringToBytes();
      final plainText = message;
      final cipherText = Uint8List(engine.outputBlockSize);
      engine.processBlock(plainText, 0, plainText.length, cipherText, 0);

      engine.init(false, PrivateKeyParameter<ElGamalPrivateKey>(privateKey));
      engine.processBlock(cipherText, 0, cipherText.length, plainText, 0);

      expect(engine.outputBlockSize, (2048 ~/ 8) - 1, reason: "2048 outputBlockSize on decryption failed.");
      expect(message, equals(plainText), reason: '2048 bit test failed');
    });

    test('key generator test', () {
      final keyGen = ElGamalKeyGenerator()
        ..init(
          ParametersWithRandom(
            ElGamalKeyGeneratorParameters(2048, 256, 64),
            Helper.secureRandom(),
          ),
        );
      final keyPair = keyGen.generateKeyPair();

      final engine = ElGamalEngine();
      engine.init(true, PublicKeyParameter<ElGamalPublicKey>(keyPair.publicKey));
      expect(engine.outputBlockSize, 2048 ~/ 4, reason: "2048 outputBlockSize on encryption failed.");

      final message = faker.randomGenerator.string(100).stringToBytes();
      final plainText = message;
      final cipherText = Uint8List(engine.outputBlockSize);
      engine.processBlock(plainText, 0, plainText.length, cipherText, 0);

      engine.init(false, PrivateKeyParameter<ElGamalPrivateKey>(keyPair.privateKey));
      expect(engine.outputBlockSize, (2048 ~/ 8) - 1, reason: "2048 outputBlockSize on decryption failed.");

      engine.processBlock(cipherText, 0, cipherText.length, plainText, 0);
      expect(message, equals(plainText), reason: '2048 bit test failed');
    });
  });

  group('DSA signer', (() {
    final prime = BigInt.parse(
        '18162137922021319783039084688936650943756676913936359487644230524033744038416716640315362119531957065117691808427264479820376952164824666951768158261158011465383622961646140102588814345836301228952436368478471605675244965240663395560393520043446488959085100446039711212792538929022066114201273802300832755863321968834472697137828335693635804943342266260626637109532050720555091308772127451653755872557451491248990382251482443887099369600464777831608990878007068814783464418617901906104198108074206903909793174142273612557335586051547777907089455850194383049226681257881252609518716935491786310874981455522347755965263');
    final order = BigInt.parse('66237724685660121164013399122464209600863963990328366006106224772467420697001');
    final generator = BigInt.parse(
        '693117913754860276426473281664845283847827874078831837566781765224888221249721170562868171267423414589469577529462100295651372077651432728133000631159241493543615314643538727517688679127996156948227084734117835362992668110067565260029784027890436946325120986252996031434727021897912364504906315612769347582107563243931645185214720978427405505592726492013000567393825423372958968113840944031967516897982342279432489751673785605929305317306465162868047750314617256208362522435739505165126345703258213171855603629264914838294962758085762547804458344916991647240641414079945072645196179749686064721950595476461703347596');
    final publicExponent = BigInt.parse(
        '4782172781034192998693423575547001875121450860285384286800905429000791264609187331114128879953098324124068264308502771574321383159125468535909140265000623111180145376619101796653939164726433685123758969904269839090078039075889777192894408978360938352224532502867949812284119229251938382586523438070582120724642233025483830096315195183698731083960541920397786806884931581765685611516570402002856528710913800628319231592500299988215432415250617341963426900030521545457294059283280813544106638008667172693314074865970063708048659226032286932981816054377197606962836326219108126026753202594298484748732919893514434857817');
    final secretExponent = BigInt.parse('4058353653331808916569051257818485824406724876273357155551230247524105887159');

    final privateKey = DSAPrivateKey(secretExponent, prime, order, generator);
    final publicKey = DSAPublicKey(publicExponent, prime, order, generator);

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

    test('key generator test', () {
      final signer = DSASigner(Digest('SHA-256'));
      final keyGen = DSAKeyGenerator()
        ..init(
          ParametersWithRandom(
            DSAKeyGeneratorParameters(2048, 256, 64),
            Helper.secureRandom(),
          ),
        );
      final keyPair = keyGen.generateKeyPair();

      signer.init(true, PrivateKeyParameter<DSAPrivateKey>(keyPair.privateKey));
      final signature = signer.generateSignature(message);
      signer.init(false, PublicKeyParameter<DSAPublicKey>(keyPair.publicKey));
      expect(signer.verifySignature(message, signature), true);
    });
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
}
