library src;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keypair.dart';
import 'stanza.dart';
import 'x25519.dart';

abstract class AgePlugin {
  static final List<AgePlugin> _plugins = [X25519AgePlugin()];

  AgePlugin();

  static void registerPlugin(AgePlugin p) {
    _plugins.add(p);
  }

  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity);

  AgeStanza? parseStanza(List<String> arguments, Uint8List body);

  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]);

  static AgeStanza? stanzaParse(List<String> arguments, Uint8List body) {
    for (var plugin in _plugins) {
      final stanza = plugin.parseStanza(arguments, body);
      if (stanza != null) {
        return stanza;
      }
    }
    return null;
  }

  static Future<AgeStanza> stanzaCreate(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    for (var plugin in _plugins) {
      final stanza = await plugin.createStanza(
          recipient, symmetricFileKey, ephemeralKeyPair);
      if (stanza != null) {
        return stanza;
      }
    }
    throw Exception('Could not create stanza!');
  }

  static Future<AgeKeyPair> convertIdentityToKeyPair(
      AgeIdentity identity) async {
    for (var plugin in _plugins) {
      final keyPair = await plugin.identityToKeyPair(identity);
      if (keyPair != null) {
        return keyPair;
      }
    }
    throw Exception('Could not create key pair!');
  }
}
