import 'dart:typed_data';

import 'package:cryptography/src/cryptography/simple_key_pair.dart';
import 'package:dage/dage.dart';
import 'package:test/test.dart';

class DummyPlugin extends AgePlugin {
  @override
  Future<AgeStanza?> createPassphraseStanza(
      Uint8List symmetricFileKey, Uint8List salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    throw UnimplementedError();
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) {
    throw UnimplementedError();
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) {
    throw UnimplementedError();
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, Uint8List body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    throw UnimplementedError();
  }
}

void main() {
  test('Plugins can be added', () async {
    AgePlugin.registerPlugin(DummyPlugin());
  });
}
