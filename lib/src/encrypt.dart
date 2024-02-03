import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';
import 'package:async/async.dart';

import 'header.dart';
import 'keypair.dart';
import 'passphrase_provider.dart';
import 'plugin/plugin.dart';
import 'random.dart';
import 'stanza.dart';

final Logger _logger = Logger('AgeEncrypt');
const chunkSize = 64 * 1024; //64KiB

Stream<List<int>> encryptWithPassphrase(Stream<List<int>> payload,
    {AgeRandom random = const AgeRandom(),
    PassphraseProvider passphraseProvider = const PassphraseProvider(),
    workFactor = -1}) async* {
  _logger.fine('Encrypting to a passphrase');
  final symmetricFileKey = random.bytes(16);
  final stanza = await AgePlugin.passphraseStanzaCreate(
      symmetricFileKey, random.bytes(16), passphraseProvider, workFactor);
  final header = await AgeHeader.create([stanza], symmetricFileKey);
  final payloadNonce = random.bytes(16);

  yield (await header.serialize()).codeUnits;
  yield [0x0a];
  yield* _encryptPayload(payload,
      symmetricFileKey: symmetricFileKey, payloadNonce: payloadNonce);
}

Stream<List<int>> encrypt(
    Stream<List<int>> payload, List<AgeRecipient> recipients,
    {AgeRandom random = const AgeRandom(), SimpleKeyPair? keyPair}) async* {
  _logger.fine('Encrypting to ${recipients.length} recipients');
  final symmetricFileKey = random.bytes(16);
  final stanzas =
      await Future.wait<AgeStanza>(recipients.map((recipient) async {
    return AgePlugin.stanzaCreate(recipient, symmetricFileKey, keyPair);
  }));
  if (stanzas.isEmpty) {
    throw Exception('Could not encrypt to any recipient!');
  }
  final header = await AgeHeader.create(stanzas, symmetricFileKey);
  final payloadNonce = random.bytes(16);
  yield (await header.serialize()).codeUnits;
  yield [0x0a];
  yield* _encryptPayload(payload,
      symmetricFileKey: symmetricFileKey, payloadNonce: payloadNonce);
}

List<int> _toBinaryCounter(int chunkCounter) {
  const byteCount = 11;
  final byteList = List<int>.filled(byteCount, 0);
  // Populate the list with bytes from the integer
  for (int i = byteCount - 1; i >= 0; i--) {
    // Extract each byte using bitwise operations
    byteList[i] = (chunkCounter & 0xFF);
    // Shift the integer to the right by 8 bits to process the next byte
    chunkCounter >>= 8;
  }
  return byteList;
}

Stream<List<int>> _encryptPayload(Stream<List<int>> payload,
    {required Uint8List symmetricFileKey,
    required Uint8List payloadNonce}) async* {
  yield payloadNonce;
  _logger.fine('Encrypting payload');
  final hkdfAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  _logger.finer('Payload nonce: $payloadNonce');
  final payloadKey = await hkdfAlgorithm.deriveKey(
      secretKey: SecretKeyData(symmetricFileKey),
      nonce: payloadNonce,
      info: 'payload'.codeUnits);
  final encryptionAlgorithm = Chacha20.poly1305Aead();
  final chunkedIterator = ChunkedStreamReader(payload);
  var chunkCounter = 0;
  try {
    Uint8List chunk;
    do {
      chunk = await chunkedIterator.readBytes(chunkSize);
      final nonceEnd = (chunk.length != chunkSize) ? [0x01] : [0x00];
      final chunkNonce = _toBinaryCounter(chunkCounter) + nonceEnd;
      _logger.finer('Chunk nonce: $chunkNonce');
      _logger.finer('Chunk length: ${chunk.length} (max: $chunkSize)');
      final secretBox = await encryptionAlgorithm.encrypt(chunk,
          nonce: chunkNonce, secretKey: payloadKey);
      _logger.finer('Chunk mac: ${secretBox.mac.bytes}');
      chunkCounter = chunkCounter + 1;
      yield secretBox.concatenation(nonce: false);
    } while (chunk.length == chunkSize);
  } finally {
    await chunkedIterator.cancel();
  }
  _logger.fine('Encryption finished');
}
