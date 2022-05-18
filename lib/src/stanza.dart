library src;

import 'dart:typed_data';

import 'keypair.dart';
import 'plugin.dart';
import 'util.dart';

abstract class AgeStanza {
  AgeStanza();

  factory AgeStanza.parse(String content) {
    final lines = content.split('\n');
    final arguments = lines[0].replaceFirst('-> ', '').split(' ');
    final body = lines.sublist(1).join('').replaceAll('\n', '');
    final stanza = AgePlugin.stanzaParse(arguments, base64RawDecode(body));
    if (stanza != null) {
      return stanza;
    }
    throw Exception('Recipient not supported: ${arguments[0]}');
  }

  Future<String> serialize();

  Future<Uint8List> decryptedFileKey(AgeKeyPair keyPair);
}
