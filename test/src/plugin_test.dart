import 'package:cryptography/cryptography.dart';
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
      [KeyPair? ephemeralKeyPair]) {
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
