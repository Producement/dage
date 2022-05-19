import 'dart:typed_data';

import 'package:dage/src/header.dart';
import 'package:dage/src/plugin/x25519.dart';
import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());

  String serialised = '''age-encryption.org/v1
-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q
1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE
--- hnTNhYFvWIIs53UDE1UqyW/PYyLD3zFmDJPTMS7/s8U''';

  test('header', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    final stanza = await X25519AgeStanza.create(
        recipientKeyPair.recipientBytes, symmetricFileKey, ephemeralKeyPair);
    final header = await AgeHeader.create([stanza], symmetricFileKey);
    expect(await header.serialize(), serialised);
  });

  test('parse header', () async {
    final header = await AgeHeader.parse(serialised);
    expect(await header.serialize(), equals(serialised));
  });

  test('incorrect version', () async {
    expect(() => AgeHeader.parse('age-encryption.org/v2'), throwsException);
  });
}
