import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dage/src/file.dart';
import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());

  final dataAsEncryptedBytes =
      hex.decode('831464304e4ea2bb7c19518b745fb3232d2cdec054052c2b');
  final nonce = Uint8List.fromList(List.generate(16, (index) => 1));
  final encryptedFile = '''age-encryption.org/v1
-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q
5JB0/RnLXiJHL29Bg7V1kWZX5+WaM8KjNryAX74lJQg
--- B8KHU7wT6kOr8cgWResfbN3irfAO3yZpt0aoR026YHs
'''
          .codeUnits +
      nonce +
      dataAsEncryptedBytes;

  test('encrypt', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    var encrypted = await AgeFile.encrypt(
        Uint8List.fromList('sinu ema'.codeUnits), [recipient],
        random: ConstAgeRandom(), keyPair: ephemeralKeyPair);
    expect(encrypted.content, orderedEquals(encryptedFile));
  });

  test('decrypt', () async {
    final file = AgeFile(Uint8List.fromList(encryptedFile));
    final decrypted = await file.decrypt([recipientKeyPair]);
    expect(String.fromCharCodes(decrypted), equals('sinu ema'));
  });

  test('encrypts and decrypts multiple chunks', () async {
    final bigFile =
        Uint8List.fromList(List.generate(1024 * 100, (index) => 0x01));
    var encrypted = await AgeFile.encrypt(bigFile, [recipient]);
    final decrypted = await encrypted.decrypt([recipientKeyPair]);
    expect(decrypted, orderedEquals(bigFile));
  });
}
