// Copyright 2023, the Blake3 project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'digest_sink.dart';

/// An interface for cryptographic hash functions.
///
/// Every hash is a converter that takes a list of ints and returns a single
/// digest.
abstract class Hash extends Converter<Uint8List, Digest> {
  /// The internal block size of the hash in bytes.
  ///
  /// This is exposed for use by the `Hmac` class,
  /// which needs to know the block size for the [Hash] it uses.
  int get blockSize;

  const Hash();

  @override
  Digest convert(List<int> input) {
    var innerSink = DigestSink();
    var outerSink = startChunkedConversion(innerSink);
    outerSink.add(input);
    outerSink.close();
    return innerSink.value;
  }

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink);
}
