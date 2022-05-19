import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dage/dage.dart';
import 'package:dage/src/plugin/x25519.dart';

void main() async {
  // Generate keypair
  final keyPair = await X25519AgePlugin.generateKeyPair();
  // Encryption
  final content = Uint8List.fromList('Hello World'.codeUnits);
  final encryptedFile = encrypt(Stream.value(content), [keyPair.recipient]);
  // Decryption
  final decrypted = decrypt(encryptedFile, [keyPair]);

  // Consume entire stream
  final bytes = await decrypted.toList();

  assert(String.fromCharCodes(bytes.flattened) == 'Hello World');
}
