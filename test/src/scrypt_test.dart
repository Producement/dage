import 'dart:typed_data';

import 'package:dage/src/extensions.dart';
import 'package:dage/src/scrypt.dart';
import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());

  final plugin = ScryptPlugin();
  test('parse stanza', () async {
    final stanza = await plugin.parseStanza(
        ['scrypt', 'zzYuo2y6OED2CG3D53V0fw', '18'],
        'bDv3uo69Okm5eK3/EgDNcG2DJWng6CvAqIVEzxM4Qmo'.base64RawDecode());
    expect(stanza, isNotNull);
  });

  test('MUST ignore if tag is not scrypt', () async {
    await expectLater(plugin.parseStanza([], Uint8List(0)), completion(isNull));
  });

  test('MUST reject if arguments length is not 3', () async {
    await expectLater(
        plugin.parseStanza(
            ['scrypt', 'zzYuo2y6OED2CG3D53V0fw', '18', 'extra'], Uint8List(0)),
        throwsA(isA<Exception>()));
  });

  test('MUST reject if second argument is not 16 bytes', () async {
    await expectLater(
        plugin.parseStanza(
            ['scrypt', 'bDv3uo69Okm5eK3/EgDNcG2DJWng6CvAqIVEzxM4Qmo', '18'],
            Uint8List(0)),
        throwsA(isA<Exception>()));
  });

  test('MUST reject if body is not 32 bytes', () async {
    await expectLater(
        plugin.parseStanza(['scrypt', 'zzYuo2y6OED2CG3D53V0fw', '18'],
            'zzYuo2y6OED2CG3D53V0fw'.base64RawDecode()),
        throwsA(isA<Exception>()));
  });
}
