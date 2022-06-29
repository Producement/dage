library age.src;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:logging/logging.dart';

final _logger = Logger('PassphraseProvider');

class PassphraseProvider {
  const PassphraseProvider();

  Future<String> passphrase() async {
    if (stdin.hasTerminal) {
      stdout.writeln('Enter passphrase: ');
      stdin.echoMode = false;
      return stdin.readLineSync()!;
    } else {
      try {
        final tty = File('/dev/tty');
        await tty.writeAsString('Enter passphrase: ');
        return _readUntilNewLine(tty);
      } catch (e, stacktrace) {
        _logger.warning('Could not get tty', e, stacktrace);
        throw Exception(
            'Standard input is not a terminal, and /dev/tty is not available');
      }
    }
  }

  Future<String> _readUntilNewLine(File tty) async {
    return tty
        .openRead()
        .map(utf8.decode)
        .transform(const LineSplitter())
        .first;
  }
}
