library src;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import 'extensions.dart';
import 'keypair.dart';
import 'passphrase_provider.dart';
import 'plugin.dart';
import 'stanza.dart';

class ScryptPlugin extends AgePlugin {
  static const _info = 'age-encryption.org/v1/scrypt';
  static const _defaultWorkFactor = 18;

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return null;
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, Uint8List body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments[0] != 'scrypt') {
      return null;
    }
    final salt = arguments[1].base64RawDecode();
    final workFactor = int.parse(arguments[2]);
    return ScryptStanza(body, salt, workFactor, passphraseProvider);
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      Uint8List symmetricFileKey, Uint8List salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    final derivator = Scrypt();
    final parameters = ScryptParameters(pow(2, _defaultWorkFactor).toInt(), 8,
        1, 32, Uint8List.fromList(_info.codeUnits + salt));
    derivator.init(parameters);
    final passphrase = passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    final wrappedKey =
        await AgeStanza.wrap(symmetricFileKey, SecretKey(derivedKey));
    return ScryptStanza(
        wrappedKey, salt, _defaultWorkFactor, passphraseProvider);
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
    final parameters = ScryptParameters(pow(2, _workFactor).toInt(), 8, 1, 32,
        Uint8List.fromList(ScryptPlugin._info.codeUnits + _salt));
    derivator.init(parameters);
    final passphrase = _passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    return AgeStanza.unwrap(_wrappedKey, SecretKey(derivedKey));
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${_salt.base64RawEncode()} $_workFactor';
    final body = _wrappedKey.base64RawEncode();
    return '${header.wrapAtPosition()}\n${body.wrapAtPosition()}';
  }
}