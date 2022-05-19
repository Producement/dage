import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dage/src/file.dart';
import 'package:dage/src/x25519.dart';

void main() async {
  // Generate keypair
  final keyPair = await X25519AgePlugin.generateKeyPair();
  // Encryption
  final content = Uint8List.fromList('Hello World'.codeUnits);
  final encryptedFile =
      AgeFile.encrypt(Stream.value(content), [keyPair.recipient]);
  // Decryption
  final decrypted = AgeFile(encryptedFile).decrypt([keyPair]);

  // Consume entire stream
  final bytes = await decrypted.toList();

  assert(String.fromCharCodes(bytes.flattened) == 'Hello World');
}
