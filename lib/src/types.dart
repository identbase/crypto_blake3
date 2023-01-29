// Copyright 2023, the Blake3 project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi';

/// Internal implementation that is required by the [Blake3Hasher] struct.
class Blake3ChunkState extends Struct {
  @Uint32()
  external int cv;

  @Uint64()
  external double chunkCounter;

  @Uint8()
  external int buf;

  @Uint8()
  external int bufLength;
  
  @Uint8()
  external int blocksCompressed;

  @Uint8()
  external int flags;
}

/// The Blake3 hasher struct that is require.
class Blake3Hasher extends Struct {
  @Uint32()
  external int key;

  external Pointer<Blake3ChunkState> cvStackLength;

  @Uint8()
  external int cvStack; 
}


/// The FFI signature of the blake3_hasher_init C fucntion.
typedef HasherInitFunc = Void Function(
  Pointer<Blake3Hasher> hasher,
);

/// The Dart type definition for calling blake3_hasher_init function.
typedef HasherInit = void Function(
  Pointer<Blake3Hasher> hasher,
);

/// The FFI signature of the blake3_hasher_update C function.
typedef HasherUpdateFunc = Void Function(
  Pointer<Blake3Hasher> hasher,
  Pointer<Void> input,
  Size length,
);

/// The Dart type definition for calling blake3_hasher_update function.
typedef HasherUpdate = void Function(
  Pointer<Blake3Hasher> hasher,
  Pointer<Void> input,
  Size length,
);

/// The FFI signature of the blake3_hasher_finalize C function.
typedef HasherFinalizeFunc = Void Function(
  Pointer<Blake3Hasher> hasher,
  Pointer<Void> output,
  Size length,
);

/// The Dart type definition for calling blake3_hasher_finalize function.
typedef HasherFinalize = void Function(
  Pointer<Blake3Hasher> hasher,
  Pointer<Void> output,
  Size length,
);

