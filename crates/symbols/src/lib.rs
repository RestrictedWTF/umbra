use common::{DebugError, Result};
use models::{TypeInfo, TypeField};
use std::collections::BTreeSet;
use std::fs::File;
use std::path::Path;
use pdb::FallibleIterator;

/// Open a PDB file and resolve type information by name.
/// Returns type size, type_id, and field offsets for UDT/class/struct/union/enum
/// types.
///
/// This is an offline parser; it does not require a live debugging session.
///
/// MSVC PDBs emit a *forward-reference* stub (size 0, no fields) for a type
/// before its real definition; those stubs are skipped so callers get the real
/// layout rather than a plausible-looking empty one.
pub fn resolve_type_from_pdb(pdb_path: &str, type_name: &str) -> Result<TypeInfo> {
    let path = Path::new(pdb_path);
    if !path.exists() {
        return Err(DebugError::InvalidParameter {
            message: format!("PDB file not found: {}", pdb_path),
        });
    }

    let file = File::open(path).map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to open PDB: {}", e),
    })?;

    let mut pdb = pdb::PDB::open(file).map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to parse PDB: {}", e),
    })?;

    let type_information = pdb.type_information().map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to read PDB type information: {}", e),
    })?;

    let mut type_finder = type_information.finder();

    let mut iter = type_information.iter();
    while let Some(typ) = iter.next().map_err(|e| DebugError::InvalidParameter {
        message: format!("PDB type iteration error: {}", e),
    })? {
        type_finder.update(&iter);

        match typ.parse() {
            Ok(pdb::TypeData::Class(class))
                if class.name.to_string() == type_name
                    && !class.properties.forward_reference() =>
            {
                let fields = match class.fields {
                    Some(idx) => extract_fields(idx, &type_finder),
                    None => Vec::new(),
                };
                return Ok(TypeInfo {
                    name: type_name.to_string(),
                    size: class.size as u32,
                    type_id: typ.index().0 as u32,
                    fields,
                });
            }
            Ok(pdb::TypeData::Union(union))
                if union.name.to_string() == type_name
                    && !union.properties.forward_reference() =>
            {
                let fields = extract_fields(union.fields, &type_finder);
                return Ok(TypeInfo {
                    name: type_name.to_string(),
                    size: union.size as u32,
                    type_id: typ.index().0 as u32,
                    fields,
                });
            }
            Ok(pdb::TypeData::Enumeration(enm))
                if enm.name.to_string() == type_name
                    && !enm.properties.forward_reference() =>
            {
                let size = type_size_from_index(enm.underlying_type, &type_finder);
                let fields = extract_enum_variants(enm.fields, &type_finder);
                return Ok(TypeInfo {
                    name: type_name.to_string(),
                    size: size as u32,
                    type_id: typ.index().0 as u32,
                    fields,
                });
            }
            _ => {}
        }
    }

    Err(DebugError::InvalidParameter {
        message: format!("Type '{}' not found in PDB {}", type_name, pdb_path),
    })
}

/// Walk a `LF_FIELDLIST` and extract its data members as `TypeField`s. Shared by
/// class/struct and union resolution (a union's members all sit at offset 0).
fn extract_fields(fields_index: pdb::TypeIndex, finder: &pdb::TypeFinder) -> Vec<TypeField> {
    let mut fields = Vec::new();
    if let Ok(field_type) = finder.find(fields_index) {
        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
            for field in field_list.fields {
                if let pdb::TypeData::Member(member) = field {
                    fields.push(TypeField {
                        name: member.name.to_string().into(),
                        offset: member.offset as u32,
                        size: type_size_from_index(member.field_type, finder) as u32,
                        type_name: type_name_from_index(member.field_type, finder),
                    });
                }
            }
        }
    }
    fields
}

/// Walk a `LF_FIELDLIST` and extract enumeration constants. Enum variants are
/// name/value pairs rather than offset-addressable members, so the constant's
/// integer value is surfaced in `type_name` (as a decimal) and `offset`/`size`
/// are 0.
fn extract_enum_variants(fields_index: pdb::TypeIndex, finder: &pdb::TypeFinder) -> Vec<TypeField> {
    let mut fields = Vec::new();
    if let Ok(field_type) = finder.find(fields_index) {
        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
            for field in field_list.fields {
                if let pdb::TypeData::Enumerate(e) = field {
                    fields.push(TypeField {
                        name: e.name.to_string().into(),
                        offset: 0,
                        size: 0,
                        type_name: format!("= {}", e.value),
                    });
                }
            }
        }
    }
    fields
}

/// Get a human-readable type name for a TypeIndex.
fn type_name_from_index(index: pdb::TypeIndex, finder: &pdb::TypeFinder) -> String {
    match finder.find(index) {
        Ok(t) => match t.parse() {
            Ok(pdb::TypeData::Primitive(p)) => {
                if p.indirection.is_some() {
                    format!("{:?}*", p.kind)
                } else {
                    format!("{:?}", p.kind)
                }
            }
            Ok(pdb::TypeData::Pointer(_)) => "pointer".to_string(),
            Ok(pdb::TypeData::Array(arr)) => {
                let elem = type_name_from_index(arr.element_type, finder);
                match array_element_count(&arr, finder) {
                    Some(n) => format!("{}[{}]", elem, n),
                    None => format!("{}[]", elem),
                }
            }
            Ok(pdb::TypeData::Class(c)) => c.name.to_string().into(),
            Ok(pdb::TypeData::Union(u)) => u.name.to_string().into(),
            Ok(pdb::TypeData::Enumeration(e)) => e.name.to_string().into(),
            // const/volatile modifier: name the underlying type with a qualifier.
            Ok(pdb::TypeData::Modifier(m)) => {
                let inner = type_name_from_index(m.underlying_type, finder);
                if m.constant {
                    format!("const {}", inner)
                } else if m.volatile {
                    format!("volatile {}", inner)
                } else {
                    inner
                }
            }
            _ => "unknown".to_string(),
        },
        Err(_) => "unknown".to_string(),
    }
}

/// Number of elements in an array, derived from its total byte size and the
/// element size. `pdb` stores dimensions as byte sizes with the top dimension
/// holding the aggregate, so the last dimension is the total size in bytes.
fn array_element_count(arr: &pdb::ArrayType, finder: &pdb::TypeFinder) -> Option<u64> {
    let total = arr.dimensions.last().copied()? as u64;
    let elem = type_size_from_index(arr.element_type, finder);
    if elem == 0 {
        None
    } else {
        Some(total / elem)
    }
}

/// Get the size of a type in bytes given its TypeIndex.
fn type_size_from_index(index: pdb::TypeIndex, finder: &pdb::TypeFinder) -> u64 {
    match finder.find(index) {
        Ok(t) => match t.parse() {
            Ok(pdb::TypeData::Primitive(p)) => primitive_type_size(&p),
            Ok(pdb::TypeData::Pointer(_)) => 8,
            // `dimensions` are byte sizes with the top dimension holding the
            // aggregate total, so the last element IS the array's byte size.
            // Multiplying by the element size (the old behaviour) double-counted.
            Ok(pdb::TypeData::Array(arr)) => arr.dimensions.last().copied().unwrap_or(0) as u64,
            Ok(pdb::TypeData::Class(c)) => c.size,
            Ok(pdb::TypeData::Union(u)) => u.size,
            Ok(pdb::TypeData::Enumeration(e)) => type_size_from_index(e.underlying_type, finder),
            // const/volatile modifiers do not change size — recurse.
            Ok(pdb::TypeData::Modifier(m)) => type_size_from_index(m.underlying_type, finder),
            _ => 0,
        },
        Err(_) => 0,
    }
}

/// Size in bytes of a pointer with the given indirection.
fn indirection_size(ind: pdb::Indirection) -> u64 {
    match ind {
        pdb::Indirection::Near16 | pdb::Indirection::Far16 | pdb::Indirection::Huge16 => 2,
        pdb::Indirection::Near32 | pdb::Indirection::Far32 => 4,
        pdb::Indirection::Near64 => 8,
        pdb::Indirection::Near128 => 16,
    }
}

/// Size in bytes of a primitive kind (ignoring pointer indirection).
fn primitive_kind_size(kind: pdb::PrimitiveKind) -> u64 {
    match kind {
        pdb::PrimitiveKind::Void => 0,
        pdb::PrimitiveKind::Char | pdb::PrimitiveKind::UChar | pdb::PrimitiveKind::I8 | pdb::PrimitiveKind::U8 | pdb::PrimitiveKind::Bool8 => 1,
        pdb::PrimitiveKind::WChar | pdb::PrimitiveKind::RChar16 | pdb::PrimitiveKind::I16 | pdb::PrimitiveKind::U16 | pdb::PrimitiveKind::Bool16 | pdb::PrimitiveKind::Short | pdb::PrimitiveKind::UShort | pdb::PrimitiveKind::HRESULT => 2,
        pdb::PrimitiveKind::I32 | pdb::PrimitiveKind::U32 | pdb::PrimitiveKind::Bool32 | pdb::PrimitiveKind::Long | pdb::PrimitiveKind::ULong | pdb::PrimitiveKind::RChar32 | pdb::PrimitiveKind::F32 => 4,
        pdb::PrimitiveKind::I64 | pdb::PrimitiveKind::U64 | pdb::PrimitiveKind::Quad | pdb::PrimitiveKind::UQuad | pdb::PrimitiveKind::F64 | pdb::PrimitiveKind::F128 | pdb::PrimitiveKind::F48 | pdb::PrimitiveKind::F80 => 8,
        _ => 8,
    }
}

/// Size of a primitive type in bytes. A primitive with pointer indirection
/// (MSVC encodes `void*`/`char*`/`PVOID` this way) is pointer-sized, NOT the
/// size of the pointee — the old code returned the pointee size (e.g. `void*`
/// -> 0, `char*` -> 1), silently corrupting struct layouts.
fn primitive_type_size(primitive: &pdb::PrimitiveType) -> u64 {
    match primitive.indirection {
        Some(ind) => indirection_size(ind),
        None => primitive_kind_size(primitive.kind),
    }
}

/// List all named types in a PDB file. Names are de-duplicated (MSVC emits a
/// forward-reference stub plus the real definition under the same name), so each
/// type appears once, sorted.
pub fn list_types_in_pdb(pdb_path: &str) -> Result<Vec<String>> {
    let path = Path::new(pdb_path);
    if !path.exists() {
        return Err(DebugError::InvalidParameter {
            message: format!("PDB file not found: {}", pdb_path),
        });
    }

    let file = File::open(path).map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to open PDB: {}", e),
    })?;

    let mut pdb = pdb::PDB::open(file).map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to parse PDB: {}", e),
    })?;

    let type_information = pdb.type_information().map_err(|e| DebugError::InvalidParameter {
        message: format!("Failed to read PDB type information: {}", e),
    })?;

    let mut types: BTreeSet<String> = BTreeSet::new();
    let mut iter = type_information.iter();
    while let Some(typ) = iter.next().map_err(|e| DebugError::InvalidParameter {
        message: format!("PDB type iteration error: {}", e),
    })? {
        match typ.parse() {
            Ok(pdb::TypeData::Class(c)) => { types.insert(c.name.to_string().into()); }
            Ok(pdb::TypeData::Union(u)) => { types.insert(u.name.to_string().into()); }
            Ok(pdb::TypeData::Enumeration(e)) => { types.insert(e.name.to_string().into()); }
            _ => {}
        }
    }

    Ok(types.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pdb::{Indirection, PrimitiveKind, PrimitiveType};

    #[test]
    fn pointer_primitives_are_pointer_sized() {
        // The bug: void*/char* reported the pointee size (0/1) instead of 8.
        let void_ptr = PrimitiveType { kind: PrimitiveKind::Void, indirection: Some(Indirection::Near64) };
        let char_ptr = PrimitiveType { kind: PrimitiveKind::Char, indirection: Some(Indirection::Near64) };
        assert_eq!(primitive_type_size(&void_ptr), 8);
        assert_eq!(primitive_type_size(&char_ptr), 8);

        let void_ptr32 = PrimitiveType { kind: PrimitiveKind::Void, indirection: Some(Indirection::Near32) };
        assert_eq!(primitive_type_size(&void_ptr32), 4);
    }

    #[test]
    fn non_pointer_primitives_keep_their_size() {
        let i32v = PrimitiveType { kind: PrimitiveKind::I32, indirection: None };
        let u64v = PrimitiveType { kind: PrimitiveKind::U64, indirection: None };
        let void = PrimitiveType { kind: PrimitiveKind::Void, indirection: None };
        assert_eq!(primitive_type_size(&i32v), 4);
        assert_eq!(primitive_type_size(&u64v), 8);
        assert_eq!(primitive_type_size(&void), 0);
    }

    #[test]
    fn indirection_sizes() {
        assert_eq!(indirection_size(Indirection::Near64), 8);
        assert_eq!(indirection_size(Indirection::Near32), 4);
        assert_eq!(indirection_size(Indirection::Near128), 16);
        assert_eq!(indirection_size(Indirection::Near16), 2);
    }

    #[test]
    fn primitive_kind_sizes() {
        assert_eq!(primitive_kind_size(PrimitiveKind::U8), 1);
        assert_eq!(primitive_kind_size(PrimitiveKind::U16), 2);
        assert_eq!(primitive_kind_size(PrimitiveKind::U32), 4);
        assert_eq!(primitive_kind_size(PrimitiveKind::U64), 8);
        assert_eq!(primitive_kind_size(PrimitiveKind::F32), 4);
        assert_eq!(primitive_kind_size(PrimitiveKind::F64), 8);
    }
}
