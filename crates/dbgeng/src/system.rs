use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSystemObjects;
use common::{DebugError, Result};

pub struct DebugSystemObjects(pub IDebugSystemObjects);

impl DebugSystemObjects {
    pub fn new(ptr: IDebugSystemObjects) -> Self {
        Self(ptr)
    }

    pub fn get_number_processes(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetNumberProcesses()
                .map_err(|e| DebugError::Com {
                    message: format!("GetNumberProcesses: {}", e),
                })
        }
    }

    pub fn get_process_id_by_index(&self, index: u32) -> Result<u32> {
        unsafe {
            let mut id = 0u32;
            self.0
                .GetProcessIdsByIndex(index, 1, Some(&mut id), None)
                .map_err(|e| DebugError::Com {
                    message: format!("GetProcessIdByIndex: {}", e),
                })?;
            Ok(id)
        }
    }

    pub fn get_current_process_id(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetCurrentProcessId()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentProcessId: {}", e),
                })
        }
    }

    /// Set the current process context by engine process id (from
    /// `GetProcessIdsByIndex`). Mutates engine-wide state — callers must restore.
    pub fn set_current_process_id(&self, id: u32) -> Result<()> {
        unsafe {
            self.0
                .SetCurrentProcessId(id)
                .map_err(|e| DebugError::Com {
                    message: format!("SetCurrentProcessId: {}", e),
                })
        }
    }

    /// OS process id (system id) of the current process context.
    pub fn get_current_process_system_id(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetCurrentProcessSystemId()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentProcessSystemId: {}", e),
                })
        }
    }

    pub fn get_current_thread_id(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetCurrentThreadId()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentThreadId: {}", e),
                })
        }
    }

    /// Set the current thread context by engine thread id (from
    /// `GetThreadIdsByIndex`). Mutates engine-wide state — callers must restore.
    pub fn set_current_thread_id(&self, id: u32) -> Result<()> {
        unsafe {
            self.0
                .SetCurrentThreadId(id)
                .map_err(|e| DebugError::Com {
                    message: format!("SetCurrentThreadId: {}", e),
                })
        }
    }

    /// OS thread id (system id) of the current thread context.
    pub fn get_current_thread_system_id(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetCurrentThreadSystemId()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentThreadSystemId: {}", e),
                })
        }
    }

    /// TEB address of the current thread context.
    pub fn get_current_thread_teb(&self) -> Result<u64> {
        unsafe {
            self.0
                .GetCurrentThreadTeb()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentThreadTeb: {}", e),
                })
        }
    }

    pub fn get_number_threads(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetNumberThreads()
                .map_err(|e| DebugError::Com {
                    message: format!("GetNumberThreads: {}", e),
                })
        }
    }

    pub fn get_thread_id_by_index(&self, index: u32) -> Result<u32> {
        unsafe {
            let mut id = 0u32;
            self.0
                .GetThreadIdsByIndex(index, 1, Some(&mut id), None)
                .map_err(|e| DebugError::Com {
                    message: format!("GetThreadIdByIndex: {}", e),
                })?;
            Ok(id)
        }
    }

    pub fn get_current_process_data_offset(&self) -> Result<u64> {
        unsafe {
            self.0
                .GetCurrentProcessDataOffset()
                .map_err(|e| DebugError::Com {
                    message: format!("GetCurrentProcessDataOffset: {}", e),
                })
        }
    }

}
