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
}
