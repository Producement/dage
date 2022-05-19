import 'dart:typed_data';

import 'package:dage/src/extensions.dart';
import 'package:dage/src/x25519.dart';
import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());
  final plugin = X25519AgePlugin();
  test('calculates recipient from identity', () async {
    final keyPair = await plugin.identityToKeyPair(identity);
    expect(keyPair, isNotNull);
    expect(keyPair!.recipientBytes, equals(recipient.bytes));
  });

  test('MUST ignore if tag is not X25519', () async {
    await expectLater(plugin.parseStanza([], Uint8List(0)), completion(isNull));
  });

  test('MUST reject if arguments length is not 2', () async {
    await expectLater(
        plugin.parseStanza(
            ['X25519', 'L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q', 'there'],
            Uint8List(0)),
        throwsA(isA<Exception>()));
  });

  test('MUST reject if second argument is not 32 bytes', () async {
    await expectLater(plugin.parseStanza(['X25519', 'hello'], Uint8List(0)),
        throwsA(isA<Exception>()));
  });

  test('MUST reject if body is not 32 bytes', () async {
    await expectLater(
        plugin.parseStanza(
            ['X25519', 'L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q'],
            Uint8List(0)),
        throwsA(isA<Exception>()));
  });

  test('can parse stanza if formed correctly', () async {
    await expectLater(
        plugin.parseStanza(
            ['X25519', 'L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q'],
            '1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE'.base64RawDecode()),
        completion(isNotNull));
  });
}
