library age.src;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keypair.dart';
import 'passphrase_provider.dart';
import 'plugin/encoding.dart';
import 'plugin/plugin.dart';

abstract class AgeStanza {
  const AgeStanza();

  static Future<AgeStanza> parse(String content,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    final lines = content.split('\n');
    final arguments = lines[0].replaceFirst('-> ', '').split(' ');
    final body = lines.sublist(1).join('').replaceAll('\n', '');
    return AgePlugin.stanzaParse(
        arguments, base64RawDecode(body), passphraseProvider);
  }

  Future<String> serialize();

  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair);

  static Future<Uint8List> wrap(
      List<int> symmetricFileKey, SecretKey derivedKey) async {
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final body = await wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: List.generate(12, (index) => 0x00));
    return body.concatenation(nonce: false);
  }

  static Future<Uint8List> unwrap(
      List<int> wrappedKey, SecretKey derivedKey) async {
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final secretBox = SecretBox.fromConcatenation(
        List.generate(12, (index) => 0x00) + wrappedKey,
        macLength: 16,
        nonceLength: 12);
    return Uint8List.fromList(
        await wrappingAlgorithm.decrypt(secretBox, secretKey: derivedKey));
  }
}
