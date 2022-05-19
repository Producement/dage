import 'dart:async';
import 'dart:typed_data';

import 'package:collection/collection.dart';
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
    var encrypted = AgeFile.encrypt(
        Stream.value('sinu ema'.codeUnits), [recipient],
        random: ConstAgeRandom(), keyPair: ephemeralKeyPair);
    final response = await encrypted.toList();
    expect(response.flattened, orderedEquals(encryptedFile));
  });

  test('decrypt', () async {
    final file = AgeFile(Stream.value(encryptedFile));
    final decrypted = file.decrypt([recipientKeyPair]);
    final response = await decrypted.toList();
    expect(String.fromCharCodes(response.flattened), equals('sinu ema'));
  });

  test('encrypts and decrypts multiple chunks', () async {
    final bigFile =
        Uint8List.fromList(List.generate(1024 * 100, (index) => 0x01));
    var encrypted = AgeFile.encrypt(Stream.value(bigFile), [recipient]);
    final decrypted = AgeFile(encrypted).decrypt([recipientKeyPair]);
    final response = await decrypted.toList();
    expect(response.flattened, orderedEquals(bigFile));
  });

  test('encrypts and decrypts with passphrase', () async {
    var encrypted = AgeFile.encryptWithPassphrase(
        Stream.value(Uint8List.fromList('sinu ema'.codeUnits)),
        passphraseProvider: ConstantPassphraseProvider());
    final decrypted =
        AgeFile(encrypted, passphraseProvider: ConstantPassphraseProvider())
            .decryptWithPassphrase();
    final response = await decrypted.toList();
    expect(String.fromCharCodes(response.flattened), equals('sinu ema'));
  });

  test('only one stanza is allowed when decrypting with a password', () async {
    final encryptedFileWithExtraStanza = '''age-encryption.org/v1
-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q
5JB0/RnLXiJHL29Bg7V1kWZX5+WaM8KjNryAX74lJQg
-> scrypt zzYuo2y6OED2CG3D53V0fw 18
bDv3uo69Okm5eK3/EgDNcG2DJWng6CvAqIVEzxM4Qmo
--- B8KHU7wT6kOr8cgWResfbN3irfAO3yZpt0aoR026YHs
'''
            .codeUnits +
        nonce +
        dataAsEncryptedBytes;
    final file = AgeFile(Stream.value(encryptedFileWithExtraStanza),
        passphraseProvider: ConstantPassphraseProvider());
    expect(file.decryptWithPassphrase(), emitsError(isA<Exception>()));
  });
}
