use windows::Win32::System::Diagnostics::Debug::Extensions::{IDebugClient, DebugCreate};

pub fn create_client() -> common::Result<IDebugClient> {
    unsafe { Ok(DebugCreate::<IDebugClient>()?) }
}
