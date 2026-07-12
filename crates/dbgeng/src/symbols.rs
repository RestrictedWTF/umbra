use windows::Win32::System::Diagnostics::Debug::Extensions::{IDebugSymbols, IDebugSymbols3};
use windows::core::{PCSTR, ComInterface};
use common::{DebugError, Result};

pub struct DebugSymbols(pub IDebugSymbols);

impl DebugSymbols {
    pub fn new(ptr: IDebugSymbols) -> Self {
        Self(ptr)
    }

    pub fn get_number_modules(&self) -> Result<u32> {
        unsafe {
            let mut loaded: u32 = 0;
            let mut unloaded: u32 = 0;
            self.0
                .GetNumberModules(&mut loaded, &mut unloaded)
                .map_err(|e| DebugError::Com {
                    message: format!("GetNumberModules: {}", e),
                })?;
            Ok(loaded)
        }
    }

    pub fn get_module_by_index(&self, index: u32) -> Result<u64> {
        unsafe {
            self.0
                .GetModuleByIndex(index)
                .map_err(|e| DebugError::Com {
                    message: format!("GetModuleByIndex: {}", e),
                })
        }
    }

    fn get_module_name_string(&self, index: u32, buffer: &mut [u8]) -> Result<u32> {
        unsafe {
            let mut needed: u32 = 0;
            self.0
                .GetModuleNames(index, 0, Some(buffer), Some(&mut needed), None, None, None, None)
                .map_err(|e| DebugError::Com {
                    message: format!("GetModuleNames: {}", e),
                })?;
            Ok(needed)
        }
    }

    fn get_module_parameters(&self, index: u32) -> Result<(u64, u32, u32)> {
        unsafe {
            let mut params = windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODULE_PARAMETERS::default();
            let idx = index as u64;
            self.0
                .GetModuleParameters(1, Some(&idx), 0, &mut params)
                .map_err(|e| DebugError::Com {
                    message: format!("GetModuleParameters: {}", e),
                })?;
            Ok((
                params.Size as u64,
                params.Checksum,
                params.TimeDateStamp,
            ))
        }
    }

    pub fn get_module_info(
        &self,
        index: u32,
    ) -> Result<(u64, String, Option<u64>, Option<u32>, Option<u32>)> {
        let base = self.get_module_by_index(index)?;
        let mut name_buf = vec![0u8; 512];
        let mut needed = self.get_module_name_string(index, &mut name_buf)? as usize;
        // If the name did not fit, re-query with an exactly-sized buffer so long
        // module paths are not silently truncated.
        if needed > name_buf.len() {
            name_buf = vec![0u8; needed];
            needed = self.get_module_name_string(index, &mut name_buf)? as usize;
        }
        let read_len = needed.min(name_buf.len());
        let len = name_buf[..read_len].iter().position(|&b| b == 0).unwrap_or(read_len);
        let name = String::from_utf8_lossy(&name_buf[..len]).to_string();
        // A failed GetModuleParameters (common on some kernel/minidump targets)
        // must not be laundered into a fabricated zero size/checksum/timestamp
        // that is indistinguishable from a real zero; report None instead.
        let (size, checksum, timestamp) = match self.get_module_parameters(index) {
            Ok((s, c, t)) => (Some(s), Some(c), Some(t)),
            Err(_) => (None, None, None),
        };
        Ok((base, name, size, checksum, timestamp))
    }

    pub fn get_offset_by_name(&self, symbol: &str) -> Result<u64> {
        unsafe {
            let cstr = std::ffi::CString::new(symbol)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);
            self.0
                .GetOffsetByName(pcstr)
                .map_err(|e| DebugError::Com {
                    message: format!("GetOffsetByName: {}", e),
                })
        }
    }

    pub fn get_symbol_type(&self, symbol: &str) -> Result<(u32, u64)> {
        unsafe {
            let cstr = std::ffi::CString::new(symbol)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);
            let mut type_id = 0u32;
            let mut module_base = 0u64;
            self.0
                .GetSymbolTypeId(pcstr, &mut type_id, Some(&mut module_base))
                .map_err(|e| DebugError::Com {
                    message: format!("GetSymbolTypeId: {}", e),
                })?;
            Ok((type_id, module_base))
        }
    }

    pub fn get_symbol_module_base(&self, symbol: &str) -> Result<u64> {
        unsafe {
            let cstr = std::ffi::CString::new(symbol)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);
            self.0
                .GetSymbolModule(pcstr)
                .map_err(|e| DebugError::Com {
                    message: format!("GetSymbolModule: {}", e),
                })
        }
    }

    /// Resolve the byte offset of `field` within `type_name` (e.g.
    /// `"nt!_KLDR_DATA_TABLE_ENTRY"`, `"DllBase"`) from symbol type information.
    /// Requires symbols with type info (public kernel symbols carry this).
    pub fn get_field_offset(&self, type_name: &str, field: &str) -> Result<u32> {
        let (type_id, module) = self.get_symbol_type(type_name)?;
        let (_field_type_id, offset) = self.get_field_type_and_offset(module, type_id, field)?;
        Ok(offset)
    }

    /// Resolve a field's `(type_id, byte_offset)` within a container type, given
    /// the container's module base and type id. Uses IDebugSymbols3.
    pub fn get_field_type_and_offset(
        &self,
        module: u64,
        container_type_id: u32,
        field: &str,
    ) -> Result<(u32, u32)> {
        let field_c = std::ffi::CString::new(field)
            .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
        let sym3 = self.0.cast::<IDebugSymbols3>().map_err(|e| DebugError::Com {
            message: format!("cast to IDebugSymbols3: {}", e),
        })?;
        unsafe {
            let mut field_type_id = 0u32;
            let mut offset = 0u32;
            sym3.GetFieldTypeAndOffset(
                module,
                container_type_id,
                PCSTR::from_raw(field_c.as_ptr() as *const u8),
                Some(&mut field_type_id),
                Some(&mut offset),
            )
            .map_err(|e| DebugError::Com {
                message: format!("GetFieldTypeAndOffset(typeid {}, {}): {}", container_type_id, field, e),
            })?;
            Ok((field_type_id, offset))
        }
    }

    /// Size in bytes of a type identified by `(module, type_id)`.
    pub fn get_type_size(&self, module: u64, type_id: u32) -> Result<u32> {
        unsafe {
            self.0
                .GetTypeSize(module, type_id)
                .map_err(|e| DebugError::Com {
                    message: format!("GetTypeSize: {}", e),
                })
        }
    }

    /// Name of a type identified by `(module, type_id)`.
    pub fn get_type_name(&self, module: u64, type_id: u32) -> Result<String> {
        unsafe {
            let mut buf = vec![0u8; 512];
            let mut needed: u32 = 0;
            self.0
                .GetTypeName(module, type_id, Some(&mut buf), Some(&mut needed))
                .map_err(|e| DebugError::Com {
                    message: format!("GetTypeName: {}", e),
                })?;
            let read = (needed as usize).min(buf.len());
            let len = buf[..read].iter().position(|&b| b == 0).unwrap_or(read);
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        }
    }

    /// Field name at `field_index` within a container type. Returns `Err` once
    /// `field_index` is past the last field, which is the natural terminator for
    /// enumerating a type's fields.
    pub fn get_field_name(&self, module: u64, type_id: u32, field_index: u32) -> Result<String> {
        let sym3 = self.0.cast::<IDebugSymbols3>().map_err(|e| DebugError::Com {
            message: format!("cast to IDebugSymbols3: {}", e),
        })?;
        unsafe {
            let mut buf = vec![0u8; 256];
            let mut needed: u32 = 0;
            sym3.GetFieldName(module, type_id, field_index, Some(&mut buf), Some(&mut needed))
                .map_err(|e| DebugError::Com {
                    message: format!("GetFieldName: {}", e),
                })?;
            let read = (needed as usize).min(buf.len());
            let len = buf[..read].iter().position(|&b| b == 0).unwrap_or(read);
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        }
    }

    pub fn reload(&self, module: &str) -> Result<()> {
        unsafe {
            let cstr = std::ffi::CString::new(module)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            self.0
                .Reload(PCSTR::from_raw(cstr.as_ptr() as *const u8))
                .map_err(|e| DebugError::Com {
                    message: format!("Reload: {}", e),
                })
        }
    }

    pub fn set_symbol_path(&self, path: &str) -> Result<()> {
        unsafe {
            let cstr = std::ffi::CString::new(path)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            self.0
                .SetSymbolPath(PCSTR::from_raw(cstr.as_ptr() as *const u8))
                .map_err(|e| DebugError::Com {
                    message: format!("SetSymbolPath: {}", e),
                })
        }
    }

    pub fn get_near_name_by_offset(
        &self,
        offset: u64,
        name_buf: &mut [u8],
        out_displ: &mut u64,
    ) -> Result<u32> {
        unsafe {
            let mut needed: u32 = 0;
            self.0
                .GetNearNameByOffset(offset, 0, Some(name_buf), Some(&mut needed), Some(out_displ))
                .map_err(|e| DebugError::Com {
                    message: format!("GetNearNameByOffset: {}", e),
                })?;
            Ok(needed)
        }
    }
}
