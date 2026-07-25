//
//  TypeImportInfo.swift
//  Echo
//
//  Created by Alejandro Alonso
//  Copyright © 2026 Alejandro Alonso. All rights reserved.
//

/// Importer-provided identity data for a nominal type.
///
/// Swift records these components after the user-facing type name for types
/// imported from C, C++, or Objective-C. The components are ordered by their
/// ABI tags: `N` for an ABI name, `S` for a symbol namespace, and `R` for a
/// synthesized related entity.
public struct TypeImportInfo: Equatable {
  /// The ABI name, when it differs from the user-facing name.
  public let abiName: String?

  /// The non-default symbol namespace used by the imported declaration.
  public let symbolNamespace: String?

  /// The name of an importer-synthesized entity related to the declaration.
  public let relatedEntityName: String?
}

extension TypeContextDescriptor {
  /// Importer-provided identity data, or `nil` when this is not an imported
  /// type or its record uses an ABI component Echo does not understand.
  public var typeImportInfo: TypeImportInfo? {
    guard typeFlags.hasImportInfo else { return nil }

    var cursor = typeNameAddress + name.utf8.count + 1
    var previousOrder = 0
    var abiName: String?
    var symbolNamespace: String?
    var relatedEntityName: String?

    while cursor.load(as: UInt8.self) != 0 {
      let component = String(cString: cursor.assumingMemoryBound(to: CChar.self))
      guard let tag = component.utf8.first,
            component.utf8.count > 1
      else { return nil }

      let value = String(component.dropFirst())
      switch tag {
      case 78: // N, ABI name
        guard previousOrder < 1 else { return nil }
        abiName = value
        previousOrder = 1
      case 83: // S, symbol namespace
        guard previousOrder < 2 else { return nil }
        symbolNamespace = value
        previousOrder = 2
      case 82: // R, related entity name
        guard previousOrder < 3 else { return nil }
        relatedEntityName = value
        previousOrder = 3
      default:
        return nil
      }
      cursor += component.utf8.count + 1
    }

    guard previousOrder > 0 else { return nil }
    return TypeImportInfo(
      abiName: abiName,
      symbolNamespace: symbolNamespace,
      relatedEntityName: relatedEntityName
    )
  }

  /// The name used by Swift's ABI for this type. Imported types may override
  /// the user-facing `name` with a stable ABI name.
  public var abiName: String {
    typeImportInfo?.abiName ?? name
  }

  var typeNameAddress: UnsafeRawPointer {
    let offset = ptr.offset(of: 2, as: Int32.self)
    return _typeDescriptor._name.address(from: offset)
  }
}
