library src;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

import 'keypair.dart';
import 'plugin.dart';
import 'stanza.dart';
import 'util.dart';

class X25519AgePlugin extends AgePlugin {
  static final algorithm = X25519();
  static const publicKeyPrefix = 'age';
  static const privateKeyPrefix = 'AGE-SECRET-KEY-';

  static Future<AgeKeyPair> generateKeyPair() async {
    final keyPair = await algorithm.newKeyPair();
    final privateKey = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    return AgeKeyPair(
        AgeIdentity(privateKeyPrefix, Uint8List.fromList(privateKey)),
        AgeRecipient(publicKeyPrefix, Uint8List.fromList(publicKey.bytes)));
  }

  @override
  AgeStanza? parseStanza(List<String> arguments, Uint8List body) {
    if (arguments[0] != 'X25519') {
      return null;
    }
    return X25519AgeStanza._(base64RawDecode(arguments[1]), body);
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
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
}

class X25519AgeStanza extends AgeStanza {
  static final logger = Logger('X25519AgeStanza');
  static const _info = 'age-encryption.org/v1/X25519';
  static const _algorithmTag = 'X25519';
  final Uint8List _ephemeralPublicKey;
  final Uint8List _wrappedKey;

  X25519AgeStanza._(this._ephemeralPublicKey, this._wrappedKey) : super();

  static Future<X25519AgeStanza> create(
      Uint8List recipientPublicKey, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    logger.info('Creating stanza');
    ephemeralKeyPair ??= await X25519AgePlugin.algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey = await _deriveKey(recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await _wrap(symmetricFileKey, derivedKey);
    return X25519AgeStanza._(
        Uint8List.fromList(ephemeralPublicKey.bytes), wrappedKey);
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${base64RawEncode(_ephemeralPublicKey)}';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }

  static Future<Uint8List> _wrap(
      Uint8List symmetricFileKey, SecretKey derivedKey) async {
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final body = await wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: List.generate(12, (index) => 0x00));
    return body.concatenation(nonce: false);
  }

  static Future<SecretKey> _deriveKey(
      Uint8List recipientPublicKey, SimpleKeyPair keyPair) async {
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
      Uint8List recipientPublicKey, SimpleKeyPair ephemeralKeypair) async {
    final remotePublicKey =
        SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519);
    var sharedSecret = await X25519AgePlugin.algorithm.sharedSecretKey(
        keyPair: ephemeralKeypair, remotePublicKey: remotePublicKey);
    return sharedSecret;
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair keyPair) async {
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
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final secretBox = SecretBox.fromConcatenation(
        List.generate(12, (index) => 0x00) + _wrappedKey,
        macLength: 16,
        nonceLength: 12);
    return Uint8List.fromList(
        await wrappingAlgorithm.decrypt(secretBox, secretKey: derivedKey));
  }
}
