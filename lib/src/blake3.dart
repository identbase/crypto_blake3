// Copyright 2023, the Blake3 project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform, Directory;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import "package:ffi/ffi.dart";
import 'package:path/path.dart' as path;
// import 'package:typed_data/typed_data.dart';

import 'hash_sink.dart';
import 'utils.dart';
// import 'types.dart';
import '../bindings/blake3.dart';


/// An implementation of the [BLAKE3][blk3] hash function.
///
/// [blk3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf 
const Hash blake3 = _Blake3._();

/// An implementation of the [BLAKE3][blk3] hash function.
///
/// [blk3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf 
///
/// Use the [blake3] object to perform SHA-256 hashing.
class _Blake3 extends Hash {
  @override
  final int blockSize = 32 * bytesPerWord;

  const _Blake3._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(_Blake3Sink256(sink, Uint32List.fromList([])));
}

/// The concrete implementation of [Blake3].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members
class _Blake3Sink256 extends HashSink {
  /// The dynamic library for [Blake3]
  late DynamicLibrary _dynamicLibrary;
  late Blake3 _blake3;
  late Pointer<blake3_hasher> _ptr;

  /// The words in the current digest.
  final Uint32List _digest;

  ///
  /// This should be updated each time [updateHash] is called.
  @override
  Uint32List get digest => _digest;

  /// Runs a single iteration of the hash computation, updating [digest] with
  /// the result.
  ///
  /// [chunk] is the current chunk, whose size is given by the
  /// `chunkSizeInWords` parameter passed to the constructor.
  @override
  void updateHash(Uint32List chunk) {

  }

  _Blake3Sink256(Sink<Digest> sink, this._digest): super(sink, 16) {
    var libraryPath =
        path.join(Directory.current.path, 'blake3_library', 'libblake3.dylib');

    if (Platform.isMacOS) {
      libraryPath =
          path.join(Directory.current.path, 'blake3_library', 'libblake3.dylib');
    }

    if (Platform.isWindows) {
      libraryPath = path.join(
          Directory.current.path, 'blake3_library', 'Debug', 'libblake3.dll');
    }

    _dynamicLibrary = DynamicLibrary.open(libraryPath);
    _blake3 = new Blake3(_dynamicLibrary);
    Pointer<blake3_hasher> ptr = calloc();

    _blake3.blake3_hasher_init(ptr);

    _ptr = ptr;
  }
}
