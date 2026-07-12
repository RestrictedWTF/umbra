use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugClient, IDebugControl, IDebugDataSpaces, IDebugRegisters, IDebugSymbols, IDebugSystemObjects,
};
use windows::core::ComInterface;
use common::{Result, DebugError};

#[derive(Clone)]
pub struct DebugClient(pub IDebugClient);

impl DebugClient {
    pub fn new(ptr: IDebugClient) -> Self {
        Self(ptr)
    }

    pub fn create_client(&self) -> Result<DebugClient> {
        unsafe {
            let new_client = self.0
                .CreateClient()
                .map_err(|e| DebugError::Com {
                    message: format!("CreateClient: {}", e),
                })?;
            Ok(DebugClient::new(new_client))
        }
    }

    pub fn attach_process(&self, server: u64, pid: u32, flags: u32) -> Result<()> {
        unsafe { Ok(self.0.AttachProcess(server, pid, flags)?) }
    }

    pub fn attach_kernel(&self, flags: u32, connect_options: &str) -> Result<()> {
        let cstr = std::ffi::CString::new(connect_options)
            .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
        let pcstr = windows::core::PCSTR::from_raw(cstr.as_ptr() as *const u8);
        unsafe { Ok(self.0.AttachKernel(flags, pcstr)?) }
    }

    pub fn end_session(&self, flags: u32) -> Result<()> {
        unsafe { Ok(self.0.EndSession(flags)?) }
    }

    // NOTE (Unicode limitation): this and the other string-taking methods here
    // use the ANSI (`...A`) engine entry points via `CString`/`PCSTR`. Paths and
    // symbols that are not representable in the active ANSI code page (e.g. a dump
    // under a non-ASCII user profile) will fail or be mangled. Fixing this
    // properly means switching to the `...Wide` methods, which in `windows` 0.52
    // live on the higher interface versions (IDebugClient4/5, IDebugControl4,
    // IDebugSymbols3) and require QueryInterface casts. Tracked as a known limit.
    pub fn open_dump_file(&self, path: &str) -> Result<()> {
        let cstr = std::ffi::CString::new(path)
            .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
        let pcstr = windows::core::PCSTR::from_raw(cstr.as_ptr() as *const u8);
        unsafe { Ok(self.0.OpenDumpFile(pcstr)?) }
    }

    pub fn query_control(&self) -> Result<super::control::DebugControl> {
        let control = self.0.cast::<IDebugControl>()?;
        Ok(super::control::DebugControl::new(control))
    }

    pub fn query_system_objects(&self) -> Result<super::system::DebugSystemObjects> {
        let system = self.0.cast::<IDebugSystemObjects>()?;
        Ok(super::system::DebugSystemObjects::new(system))
    }

    pub fn query_symbols(&self) -> Result<super::symbols::DebugSymbols> {
        let symbols = self.0.cast::<IDebugSymbols>()?;
        Ok(super::symbols::DebugSymbols::new(symbols))
    }

    pub fn query_registers(&self) -> Result<super::registers::DebugRegisters> {
        let registers = self.0.cast::<IDebugRegisters>()?;
        Ok(super::registers::DebugRegisters::new(registers))
    }

    pub fn query_data_spaces(&self) -> Result<super::data::DebugDataSpaces> {
        let data = self.0.cast::<IDebugDataSpaces>()?;
        Ok(super::data::DebugDataSpaces::new(data))
    }
}
