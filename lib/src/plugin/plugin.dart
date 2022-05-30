library age.plugin;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../keypair.dart';
import '../passphrase_provider.dart';
import 'scrypt.dart';
import '../stanza.dart';
import 'x25519.dart';

abstract class AgePlugin {
  static final List<AgePlugin> _plugins =
      List.of([X25519AgePlugin(), ScryptPlugin()]);

  const AgePlugin();

  static void registerPlugin(AgePlugin p) {
    _plugins.add(p);
  }

  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity);

  Future<AgeStanza?> parseStanza(List<String> arguments, Uint8List body,
      {PassphraseProvider passphraseProvider});

  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]);

  Future<AgeStanza?> createPassphraseStanza(
      Uint8List symmetricFileKey, Uint8List salt,
      {PassphraseProvider passphraseProvider});

  static T firstPluginSync<T>(T? Function(AgePlugin plugin) func) {
    for (var plugin in _plugins) {
      final result = func(plugin);
      if (result != null) {
        return result;
      }
    }
    throw Exception('None of the plugins could handle the function!');
  }

  static Future<T> firstPlugin<T>(
      Future<T?> Function(AgePlugin plugin) func) async {
    for (var plugin in _plugins) {
      final result = await func(plugin);
      if (result != null) {
        return result;
      }
    }
    throw Exception('None of the plugins could handle the function!');
  }

  static Future<AgeStanza> stanzaParse(List<String> arguments, Uint8List body,
      PassphraseProvider passphraseProvider) async {
    return firstPlugin((plugin) => plugin.parseStanza(arguments, body,
        passphraseProvider: passphraseProvider));
  }

  static Future<AgeStanza> stanzaCreate(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return firstPlugin((plugin) =>
        plugin.createStanza(recipient, symmetricFileKey, ephemeralKeyPair));
  }

  static Future<AgeStanza> passphraseStanzaCreate(Uint8List symmetricFileKey,
      Uint8List salt, PassphraseProvider passphraseProvider) async {
    return firstPlugin((plugin) => plugin.createPassphraseStanza(
        symmetricFileKey, salt,
        passphraseProvider: passphraseProvider));
  }

  static Future<AgeKeyPair> convertIdentityToKeyPair(
      AgeIdentity identity) async {
    return firstPlugin((plugin) => plugin.identityToKeyPair(identity));
  }
}
