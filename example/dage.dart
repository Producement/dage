import 'dart:typed_data';

import 'package:dage/src/file.dart';
import 'package:dage/src/x25519.dart';

void main() async {
  // Generate keypair
  final keyPair = await X25519AgePlugin.generateKeyPair();
  // Encryption
  final content = Uint8List.fromList('Hello World'.codeUnits);
  final encryptedFile = await AgeFile.encrypt(content, [keyPair.recipient]);
  //Decryption
  final decrypted = await encryptedFile.decrypt([keyPair]);

  assert(String.fromCharCodes(decrypted) == 'Hello World');
}
