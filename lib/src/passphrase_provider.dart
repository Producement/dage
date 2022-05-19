library age.src;

import 'dart:io';

class PassphraseProvider {
  const PassphraseProvider();

  String passphrase() {
    print('Enter passphrase:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }
}
