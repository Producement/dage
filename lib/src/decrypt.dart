library age.src;

import 'dart:convert';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dage/src/stream.dart';
import 'package:logging/logging.dart';

import 'encrypt.dart';
import 'header.dart';
import 'keypair.dart';
import 'passphrase_provider.dart';

final Logger _logger = Logger('AgeDecrypt');

const _macSize = 16;

Stream<List<int>> decrypt(Stream<List<int>> content, List<AgeKeyPair> keyPairs,
    {PassphraseProvider passphraseProvider =
        const PassphraseProvider()}) async* {
  final split = AgeStream(content);
  final rawHeader = await split.header.stream.toList();
  final header = await AgeHeader.parse(
      utf8.decode(rawHeader.flattened.toList()),
      passphraseProvider: passphraseProvider);
  Uint8List? symmetricFileKey;
  _logger.fine(
      'We have ${keyPairs.length} keypairs and ${header.stanzas.length} stanzas');
  for (var keyPair in keyPairs) {
    for (var stanza in header.stanzas) {
      try {
        symmetricFileKey = await stanza.decryptedFileKey(keyPair);
      } catch (e, stacktrace) {
        _logger.warning('Did not create key', e, stacktrace);
        //Ignore
      }
    }
  }
  if (symmetricFileKey == null) {
    throw Exception('Recipient not found');
  }
  await header.checkMac(symmetricFileKey);
  yield* _decryptPayload(split.payload.stream,
      symmetricFileKey: symmetricFileKey);
}

Stream<List<int>> decryptWithPassphrase(Stream<List<int>> content,
    {PassphraseProvider passphraseProvider =
        const PassphraseProvider()}) async* {
  final split = AgeStream(content);
  final rawHeader = await split.header.stream.toList();
  final header = await AgeHeader.parse(
      utf8.decode(rawHeader.flattened.toList()),
      passphraseProvider: passphraseProvider);
  if (header.stanzas.length != 1) {
    throw Exception('Only one recipient allowed!');
  }
  final stanza = header.stanzas.first;
  final Uint8List symmetricFileKey = await stanza.decryptedFileKey(null);
  await header.checkMac(symmetricFileKey);
  yield* _decryptPayload(split.payload.stream,
      symmetricFileKey: symmetricFileKey);
}

Stream<List<int>> _decryptPayload(Stream<List<int>> payload,
    {required Uint8List symmetricFileKey}) async* {
  _logger.fine('Decrypting payload');
  final hkdfAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final chunkedIterator = ChunkedStreamReader(payload);

  try {
    final payloadNonce = await chunkedIterator.readBytes(16);
    _logger.finer('Payload nonce: $payloadNonce');
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: payloadNonce,
        info: 'payload'.codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();

    const chunkWithMacSize = chunkSize + _macSize;
    Uint8List chunk;
    do {
      chunk = await chunkedIterator.readBytes(chunkWithMacSize);
      final nonceEnd = (chunk.length != chunkWithMacSize) ? [0x01] : [0x00];
      final chunkNonce = List.generate(11, (index) => 0) + nonceEnd;
      _logger.finer('Chunk nonce: $chunkNonce');
      _logger.finer('Chunk length: ${chunk.length}  (max: $chunkWithMacSize)');
      _logger.finer('Chunk mac: ${chunk.skip(chunk.length - _macSize)}');
      final secretBox = SecretBox.fromConcatenation(chunkNonce + chunk,
          nonceLength: 12, macLength: _macSize);
      final decrypted =
          await encryptionAlgorithm.decrypt(secretBox, secretKey: payloadKey);
      yield decrypted;
    } while (chunk.length == chunkWithMacSize);
  } finally {
    await chunkedIterator.cancel();
  }
  _logger.fine('Decryption finished');
}
