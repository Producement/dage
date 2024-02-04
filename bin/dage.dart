import 'dart:io';

import 'package:args/args.dart';
import 'package:collection/collection.dart';
import 'package:dage/dage.dart';
import 'package:logging/logging.dart';

final logger = Logger('Dage');

void main(List<String> arguments) async {
  Logger.root.onRecord.listen((record) {
    stderr.writeln(record);
    if (record.error != null) {
      stderr.writeln(record.error);
    }
    if (record.stackTrace != null) {
      stderr.writeln(record.stackTrace);
    }
  });

  final results = parseArguments(arguments);

  if (results['verbose']) {
    Logger.root.level = Level.FINE;
  }

  try {
    if (results['encrypt']) {
      final recipients = results['recipient'] as List<String>;
      final keyPairs =
          recipients.map((recipient) => AgeRecipient.fromBech32(recipient));
      final isPassphraseEncryption = results['passphrase'] as bool;
      if (keyPairs.isEmpty && !isPassphraseEncryption) {
        throw Exception('At least one recipient needed!');
      }
      if (isPassphraseEncryption) {
        final encrypted = encryptWithPassphrase(await readFromInput(results));
        await writeToOut(results, encrypted);
      } else {
        final encrypted =
            encrypt(await readFromInput(results), keyPairs.toList());
        await writeToOut(results, encrypted);
      }
    } else if (results['decrypt']) {
      final identityList = results['identity'] as List<String>;
      if (identityList.isNotEmpty) {
        final identities = await getIdentities(results);
        final decrypted = decrypt(await readFromInput(results), identities);
        await writeToOut(results, decrypted);
      } else {
        final decrypted = decryptWithPassphrase(await readFromInput(results));
        await writeToOut(results, decrypted);
      }
    }
  } catch (e, stacktrace) {
    logger.severe('Did not finish successfully', e, stacktrace);
    exit(1);
  }
}

Future<List<AgeKeyPair>> getIdentities(ArgResults results) async {
  final identityFiles = results['identity'] as List<String>;
  final keyPairs = await Future.wait(identityFiles.map((identityFile) async {
    final content = File(identityFile).readAsLinesSync();
    final key = content.firstWhere((element) => !element.startsWith('#'));
    return AgePlugin.convertIdentityToKeyPair(AgeIdentity.fromBech32(key));
  }));
  return keyPairs.toList();
}

Future<Stream<List<int>>> readFromInput(ArgResults results) async {
  if (results.rest.isNotEmpty) {
    final file = File(results.rest.last);
    if (await isArmored(file)) {
      final bytes = await file.openRead().toList();
      return Stream.value(armorDecoder.convert(bytes.flattened.toList()));
    }
    return file.openRead();
  } else {
    return stdin;
  }
}

Future<void> writeToOut(ArgResults results, Stream<List<int>> bytes) async {
  final output = results['output'];
  if (output != null) {
    if (results['armored']) {
      final bytesList = await bytes.toList();
      bytes = Stream.value(armorEncoder.convert(bytesList.flattened.toList()));
    }
    await File(output).openWrite().addStream(bytes);
  } else {
    await stdout.addStream(bytes);
  }
}

ArgResults parseArguments(List<String> arguments) {
  final parser = ArgParser();

  parser.addFlag('passphrase',
      abbr: 'p', negatable: false, help: 'Encrypt with a passphrase.');
  parser.addFlag('encrypt',
      abbr: 'e', negatable: false, help: 'Encrypt the input to the output.');
  parser.addFlag('decrypt',
      abbr: 'd', negatable: false, help: 'Decrypt the input to the output.');
  parser.addFlag('usage',
      abbr: 'u', negatable: false, help: 'Outputs this usage.');
  parser.addFlag('verbose',
      abbr: 'v', negatable: false, help: 'Enables logging to standard error.');
  parser.addOption('output',
      abbr: 'o', help: 'Write the result to the file at path.');
  parser.addMultiOption('recipient',
      abbr: 'r', help: 'Encrypt to the specified RECIPIENT. Can be repeated.');
  parser.addMultiOption('identity',
      abbr: 'i', help: 'Use the identity file at PATH. Can be repeated.');
  parser.addFlag('armored',
      abbr: 'a',
      negatable: false,
      help: 'Write the result as an armored file.');

  final results = parser.parse(arguments);

  if (results['usage'] || results.arguments.isEmpty) {
    stdout.writeln(parser.usage);
    stdout.writeln('''

INPUT defaults to standard input, and OUTPUT defaults to standard output.
If OUTPUT exists, it will be overwritten.''');
    exit(0);
  }
  return results;
}
