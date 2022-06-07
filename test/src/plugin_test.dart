import 'package:cryptography/src/cryptography/simple_key_pair.dart';
import 'package:dage/dage.dart';
import 'package:test/test.dart';

class DummyPlugin extends AgePlugin {
  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    throw UnimplementedError();
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) {
    throw UnimplementedError();
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) {
    throw UnimplementedError();
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
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
