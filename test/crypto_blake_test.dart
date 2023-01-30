import 'dart:convert';

import 'package:crypto_blake/crypto_blake.dart';
import 'package:test/test.dart';


void main() {
  group('Blake3 256', () {
    final bytes = utf8.encode("foo");

    blake3.convert(bytes);
  });
}
