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
}
