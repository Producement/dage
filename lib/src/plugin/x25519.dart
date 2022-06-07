library src;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

import '../keypair.dart';
import '../passphrase_provider.dart';
import '../stanza.dart';
import 'encoding.dart';
import 'plugin.dart';

class X25519AgePlugin extends AgePlugin {
  static final algorithm = X25519();
  static const publicKeyPrefix = 'age';
  static const privateKeyPrefix = 'AGE-SECRET-KEY-';

  const X25519AgePlugin();

  static Future<AgeKeyPair> generateKeyPair() async {
    final keyPair = await algorithm.newKeyPair();
    final privateKey = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    return AgeKeyPair(
        AgeIdentity(privateKeyPrefix, Uint8List.fromList(privateKey)),
        AgeRecipient(publicKeyPrefix, Uint8List.fromList(publicKey.bytes)));
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments.isEmpty || arguments[0] != 'X25519') {
      return null;
    }
    if (arguments.length != 2) {
      throw Exception('Wrong amount of arguments: ${arguments.length}!');
    }
    final ephemeralShare = base64RawDecode(arguments[1]);
    if (ephemeralShare.length != 32) {
      throw Exception('Ephemeral share size is incorrect!');
    }
    if (body.length != 32) {
      throw Exception('Body size is incorrect!');
    }
    return X25519AgeStanza._(ephemeralShare, body);
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    if (recipient.prefix != publicKeyPrefix) {
      return null;
    }
    return X25519AgeStanza.create(
        recipient.bytes, symmetricFileKey, ephemeralKeyPair);
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    final simpleKeyPair = await algorithm.newKeyPairFromSeed(identity.bytes);
    final publicKey = await simpleKeyPair.extractPublicKey();
    return AgeKeyPair(identity,
        AgeRecipient(publicKeyPrefix, Uint8List.fromList(publicKey.bytes)));
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    return null;
  }
}

class X25519AgeStanza extends AgeStanza {
  static final logger = Logger('X25519AgeStanza');
  static const _info = 'age-encryption.org/v1/X25519';
  static const _algorithmTag = 'X25519';
  final List<int> _ephemeralPublicKey;
  final List<int> _wrappedKey;

  const X25519AgeStanza._(this._ephemeralPublicKey, this._wrappedKey) : super();

  static Future<X25519AgeStanza> create(
      List<int> recipientPublicKey, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    logger.info('Creating stanza');
    ephemeralKeyPair ??= await X25519AgePlugin.algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey = await _deriveKey(recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await AgeStanza.wrap(symmetricFileKey, derivedKey);
    return X25519AgeStanza._(
        Uint8List.fromList(ephemeralPublicKey.bytes), wrappedKey);
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${base64RawEncode(_ephemeralPublicKey)}';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }

  static Future<SecretKey> _deriveKey(
      List<int> recipientPublicKey, SimpleKeyPair keyPair) async {
    final sharedSecret = await _sharedSecret(recipientPublicKey, keyPair);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = (await keyPair.extractPublicKey()).bytes + recipientPublicKey;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return derivedKey;
  }

  static Future<SecretKey> _sharedSecret(
      List<int> recipientPublicKey, SimpleKeyPair ephemeralKeypair) async {
    final remotePublicKey =
        SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519);
    final sharedSecret = await X25519AgePlugin.algorithm.sharedSecretKey(
        keyPair: ephemeralKeypair, remotePublicKey: remotePublicKey);
    final sharedSecretBytes = await sharedSecret.extractBytes();
    if (sharedSecretBytes.every((element) => element == 0x00)) {
      throw Exception('All shared secret bytes are 0x00!');
    }
    return sharedSecret;
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair) async {
    if (keyPair == null) {
      throw Exception('Keypair not provided!');
    }
    final simpleKeyPair = SimpleKeyPairData(keyPair.identityBytes!,
        publicKey:
            SimplePublicKey(keyPair.recipientBytes, type: KeyPairType.x25519),
        type: KeyPairType.x25519);
    final ephemeralPublicKey =
        SimplePublicKey(_ephemeralPublicKey, type: KeyPairType.x25519);
    final sharedSecret = await X25519AgePlugin.algorithm.sharedSecretKey(
        keyPair: simpleKeyPair, remotePublicKey: ephemeralPublicKey);

    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = ephemeralPublicKey.bytes + keyPair.recipientBytes;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return AgeStanza.unwrap(_wrappedKey, derivedKey);
  }
}
