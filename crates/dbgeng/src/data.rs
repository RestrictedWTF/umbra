use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugDataSpaces;
use common::{DebugError, Result};

pub struct DebugDataSpaces(pub IDebugDataSpaces);

impl DebugDataSpaces {
    pub fn new(ptr: IDebugDataSpaces) -> Self {
        Self(ptr)
    }

    pub fn read_virtual(&self, address: u64, buffer: &mut [u8]) -> Result<u32> {
        unsafe {
            let mut read: u32 = 0;
            self.0
                .ReadVirtual(
                    address,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    buffer.len() as u32,
                    Some(&mut read),
                )
                .map_err(|e| DebugError::Com {
                    message: format!("ReadVirtual: {}", e),
                })?;
            Ok(read)
        }
    }

    /// Read exactly `N` bytes at `address`, erroring on a short read.
    fn read_exact<const N: usize>(&self, address: u64) -> Result<[u8; N]> {
        let mut buf = [0u8; N];
        let read = self.read_virtual(address, &mut buf)?;
        if (read as usize) < N {
            return Err(DebugError::Target {
                message: format!("short read at 0x{:x}: got {} of {} bytes", address, read, N),
            });
        }
        Ok(buf)
    }

    pub fn read_u8(&self, address: u64) -> Result<u8> {
        Ok(self.read_exact::<1>(address)?[0])
    }

    pub fn read_u16(&self, address: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_exact::<2>(address)?))
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_exact::<4>(address)?))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_exact::<8>(address)?))
    }

    pub fn write_virtual(&self, address: u64, data: &[u8]) -> Result<u32> {
        unsafe {
            let mut written: u32 = 0;
            self.0
                .WriteVirtual(
                    address,
                    data.as_ptr() as *const std::ffi::c_void,
                    data.len() as u32,
                    Some(&mut written),
                )
                .map_err(|e| DebugError::Com {
                    message: format!("WriteVirtual: {}", e),
                })?;
            Ok(written)
        }
    }
}
