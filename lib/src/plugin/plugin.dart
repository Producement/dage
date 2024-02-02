library age.plugin;

import 'package:cryptography/cryptography.dart';

import '../keypair.dart';
import '../passphrase_provider.dart';
import '../stanza.dart';
import 'scrypt.dart';
import 'x25519.dart';

class PluginNotFoundException implements Exception {
  final String cause;

  PluginNotFoundException(this.cause);
}

abstract class AgePlugin {
  static final List<AgePlugin> _plugins =
      List.of([const X25519AgePlugin(), const ScryptPlugin()]);

  const AgePlugin();

  static void registerPlugin(AgePlugin p) {
    _plugins.add(p);
  }

  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity);

  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
      {PassphraseProvider passphraseProvider});

  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [KeyPair? ephemeralKeyPair]);

  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider});

  static T firstPluginSync<T>(T? Function(AgePlugin plugin) func) {
    for (var plugin in _plugins) {
      final result = func(plugin);
      if (result != null) {
        return result;
      }
    }
    throw PluginNotFoundException(
        'None of the plugins could handle the function!');
  }

  static Future<T> firstPlugin<T>(
      Future<T?> Function(AgePlugin plugin) func) async {
    for (var plugin in _plugins) {
      final result = await func(plugin);
      if (result != null) {
        return result;
      }
    }
    throw PluginNotFoundException(
        'None of the plugins could handle the function!');
  }

  static Future<AgeStanza> stanzaParse(List<String> arguments, List<int> body,
      PassphraseProvider passphraseProvider) async {
    try {
      return await firstPlugin((plugin) => plugin.parseStanza(arguments, body,
          passphraseProvider: passphraseProvider));
    } on PluginNotFoundException {
      return UnknownStanza(arguments, body);
    }
  }

  static Future<AgeStanza> stanzaCreate(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return firstPlugin((plugin) =>
        plugin.createStanza(recipient, symmetricFileKey, ephemeralKeyPair));
  }

  static Future<AgeStanza> passphraseStanzaCreate(List<int> symmetricFileKey,
      List<int> salt, PassphraseProvider passphraseProvider) async {
    return firstPlugin((plugin) => plugin.createPassphraseStanza(
        symmetricFileKey, salt,
        passphraseProvider: passphraseProvider));
  }

  static Future<AgeKeyPair> convertIdentityToKeyPair(
      AgeIdentity identity) async {
    return firstPlugin((plugin) => plugin.identityToKeyPair(identity));
  }
}
