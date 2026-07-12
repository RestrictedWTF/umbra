use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugRegisters;
use common::{DebugError, Result};

pub struct DebugRegisters(pub IDebugRegisters);

impl DebugRegisters {
    pub fn new(ptr: IDebugRegisters) -> Self {
        Self(ptr)
    }

    pub fn get_number_registers(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetNumberRegisters()
                .map_err(|e| DebugError::Com {
                    message: format!("GetNumberRegisters: {}", e),
                })
        }
    }

    pub fn get_value(
        &self,
        index: u32,
        out_value: &mut windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_VALUE,
    ) -> Result<()> {
        unsafe {
            self.0
                .GetValue(index, out_value)
                .map_err(|e| DebugError::Com {
                    message: format!("GetValue: {}", e),
                })
        }
    }

    pub fn get_description(
        &self,
        index: u32,
    ) -> Result<(String, windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_REGISTER_DESCRIPTION)> {
        unsafe {
            let mut name_buf = [0u8; 256];
            let mut name_size = 0u32;
            let mut desc =
                windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_REGISTER_DESCRIPTION::default();
            self.0
                .GetDescription(index, Some(&mut name_buf), Some(&mut name_size), Some(&mut desc))
                .map_err(|e| DebugError::Com {
                    message: format!("GetDescription: {}", e),
                })?;
            let read_len = (name_size as usize).min(name_buf.len());
            let name_len = name_buf[..read_len].iter().position(|&b| b == 0).unwrap_or(read_len);
            let name = String::from_utf8_lossy(&name_buf[..name_len]).to_string();
            Ok((name, desc))
        }
    }
}
