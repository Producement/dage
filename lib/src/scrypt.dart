import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dage/src/keypair.dart';
import 'package:dage/src/plugin.dart';
import 'package:dage/src/stanza.dart';
import 'package:dage/src/util.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/pointycastle.dart';

class ScryptPlugin extends AgePlugin {
  static const _info = 'age-encryption.org/v1/scrypt';

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return null;
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) {
    // TODO: implement identityToKeyPair
    throw UnimplementedError();
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, Uint8List body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments[0] != 'scrypt') {
      return null;
    }
    final salt = base64RawDecode(arguments[1]);
    final workFactor = int.parse(arguments[2]);
    return ScryptStanza(body, salt, workFactor, passphraseProvider);
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      Uint8List symmetricFileKey, Uint8List salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    final derivator = Scrypt();
    final parameters = ScryptParameters(
        16, 8, 1, 32, Uint8List.fromList(_info.codeUnits + salt));
    derivator.init(parameters);
    final passphrase = passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    final wrappedKey =
        await AgeStanza.wrap(symmetricFileKey, SecretKey(derivedKey));
    return ScryptStanza(wrappedKey, salt, 16, passphraseProvider);
  }
}

class ScryptStanza extends AgeStanza {
  static const _algorithmTag = 'scrypt';
  final Uint8List _wrappedKey;
  final Uint8List _salt;
  final int _workFactor;
  final PassphraseProvider _passphraseProvider;

  ScryptStanza(
      this._wrappedKey, this._salt, this._workFactor, this._passphraseProvider);

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair) async {
    final derivator = Scrypt();
    final parameters = ScryptParameters(_workFactor, 8, 1, 32,
        Uint8List.fromList(ScryptPlugin._info.codeUnits + _salt));
    derivator.init(parameters);
    final passphrase = _passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    return AgeStanza.unwrap(_wrappedKey, SecretKey(derivedKey));
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${base64RawEncode(_salt)} $_workFactor';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }
}

class PassphraseProvider {
  const PassphraseProvider();

  String passphrase() {
    print('Enter passphrase:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }
}
