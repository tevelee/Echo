//
//  KnownMetadata.h
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2020 Alejandro Alonso. All rights reserved.
//

#ifndef KNOWN_METADATA_H
#define KNOWN_METADATA_H

// The mangling scheme for builtin metadata is:
// $s SYMBOL N
// $s = Swift mangling prefix
// SYMBOL = The builtin type mangling
// N = Metadata
// Example: Builtin.NativeObject Metadata is $sBoN
//
// Reference the runtime defined metadata variable for builtin types.
//
// Declared as `char` rather than `void`: only the symbol's *address* is ever
// used (see KnownMetadata.c), and `extern void x;` is a GNU C extension that
// is illegal in C++. Declaring it `char` keeps the same undefined symbol
// reference and the same byte-wise pointer arithmetic while letting this
// header be included from a Swift target that enables C++ interoperability,
// which reparses every imported header as C++.
#define BUILTIN(NAME, SYMBOL) \
extern char $s##SYMBOL##N;
#include "Builtins.def"

#undef BUILTIN

// Define this utility function because you can't see variables that start with
// $ in Swift.
#define BUILTIN(NAME, SYMBOL) \
void *getBuiltin##NAME##Metadata(void);
#include "Builtins.def"

#undef BUILTIN

#endif /* KNOWN_METADATA_H */
