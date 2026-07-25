//
//  Functions.c
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2019 - 2021 Alejandro Alonso. All rights reserved.
//

#include "include/Functions.h"

#ifndef __has_attribute
#define __has_attribute(attribute) 0
#endif

#if !__has_attribute(swiftcall)
#error "Echo's Swift runtime bridge requires compiler support for swiftcall."
#endif

// These private declarations must use the Swift runtime calling convention.
// In particular, the runtime returns both pointers in registers on supported
// platforms, which can differ from an ordinary C structure return.
typedef struct SwiftRuntimeBoxPair {
  void *heapObj;
  void *buffer;
} SwiftRuntimeBoxPair;

extern __attribute__((swiftcall)) SwiftRuntimeBoxPair
swift_allocBox(const void *type);

extern __attribute__((swiftcall)) SwiftRuntimeBoxPair
swift_makeBoxUnique(void *buffer, const void *type, size_t alignMask);

extern __attribute__((swiftcall)) MetadataResponse
swift_getAssociatedTypeWitness(size_t request, const void *witnessTable,
                               const void *conformingType,
                               const void *requirementBase,
                               const void *associatedTypeRequirement);

EchoBoxPair echo_swift_allocBox(const void *type) {
  SwiftRuntimeBoxPair pair = swift_allocBox(type);
  return (EchoBoxPair){pair.heapObj, pair.buffer};
}

EchoBoxPair echo_swift_makeBoxUnique(void *buffer, const void *type,
                                     size_t alignMask) {
  SwiftRuntimeBoxPair pair = swift_makeBoxUnique(buffer, type, alignMask);
  return (EchoBoxPair){pair.heapObj, pair.buffer};
}

MetadataResponse echo_swift_getAssociatedTypeWitness(
    size_t request, const void *witnessTable, const void *conformingType,
    const void *requirementBase, const void *associatedTypeRequirement) {
  return swift_getAssociatedTypeWitness(request, witnessTable, conformingType,
                                        requirementBase,
                                        associatedTypeRequirement);
}

#if defined(__arm64e__)
#include <ptrauth.h>

const void *__ptrauth_strip_asda(const void *ptr) {
  return ptrauth_strip(ptr, ptrauth_key_asda);
}

#endif
