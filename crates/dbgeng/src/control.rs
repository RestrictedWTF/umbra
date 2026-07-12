use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl;
use windows::core::PCSTR;
use common::{DebugError, Result};

#[derive(Clone)]
pub struct DebugControl(pub IDebugControl);

impl DebugControl {
    pub fn new(ptr: IDebugControl) -> Self {
        Self(ptr)
    }

    pub fn set_interrupt(&self, flags: u32) -> Result<()> {
        unsafe {
            self.0
                .SetInterrupt(flags)
                .map_err(|e| DebugError::Com {
                    message: format!("SetInterrupt: {}", e),
                })
        }
    }

    pub fn set_execution_status(&self, status: u32) -> Result<()> {
        unsafe {
            self.0
                .SetExecutionStatus(status)
                .map_err(|e| DebugError::Com {
                    message: format!("SetExecutionStatus: {}", e),
                })
        }
    }

    pub fn get_execution_status(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetExecutionStatus()
                .map_err(|e| DebugError::Com {
                    message: format!("GetExecutionStatus: {}", e),
                })
        }
    }

    pub fn add_engine_options(&self, options: u32) -> Result<()> {
        unsafe {
            self.0
                .AddEngineOptions(options)
                .map_err(|e| DebugError::Com {
                    message: format!("AddEngineOptions: {}", e),
                })
        }
    }

    pub fn wait_for_event(&self, flags: u32, timeout: u32) -> Result<()> {
        unsafe {
            self.0
                .WaitForEvent(flags, timeout)
                .map_err(|e| DebugError::Com {
                    message: format!("WaitForEvent: {}", e),
                })
        }
    }

    pub fn execute(&self, output: u32, command: &str, flags: u32) -> Result<()> {
        unsafe {
            let cstr = std::ffi::CString::new(command)
                .map_err(|e| DebugError::InvalidParameter { message: e.to_string() })?;
            let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);
            self.0
                .Execute(output, pcstr, flags)
                .map_err(|e| DebugError::Com {
                    message: format!("Execute: {}", e),
                })
        }
    }

    fn get_number_breakpoints(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetNumberBreakpoints()
                .map_err(|e| DebugError::Com {
                    message: format!("GetNumberBreakpoints: {}", e),
                })
        }
    }

    /// Remove a breakpoint and surrender ownership of its COM interface.
    ///
    /// DbgEng deletes the breakpoint object inside RemoveBreakpoint; the
    /// IDebugBreakpoint pointer is invalid immediately after the call, so the
    /// normal Release-on-drop performed by the windows-rs smart pointer would
    /// access freed memory. Forgetting the wrapper prevents that use-after-free.
    unsafe fn remove_breakpoint_internal(&self, bp: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugBreakpoint) -> Result<()> {
        let result = self.0
            .RemoveBreakpoint(&bp)
            .map_err(|e| DebugError::Com {
                message: format!("RemoveBreakpoint: {}", e),
            });
        std::mem::forget(bp);
        result
    }

    pub fn add_breakpoint(&self, address: u64) -> Result<u32> {
        unsafe {
            let bp = self.0
                .AddBreakpoint(0, 0xffffffff)
                .map_err(|e| DebugError::Com {
                    message: format!("AddBreakpoint: {}", e),
                })?;
            if let Err(e) = bp.SetOffset(address) {
                let _ = self.remove_breakpoint_internal(bp);
                return Err(DebugError::Com {
                    message: format!("SetOffset: {}", e),
                });
            }
            if let Err(e) = bp.AddFlags(windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_ENABLED) {
                let _ = self.remove_breakpoint_internal(bp);
                return Err(DebugError::Com {
                    message: format!("AddFlags: {}", e),
                });
            }
            let id = bp.GetId()
                .map_err(|e| {
                    let _ = self.remove_breakpoint_internal(bp);
                    DebugError::Com {
                        message: format!("GetId: {}", e),
                    }
                })?;
            Ok(id)
        }
    }

    pub fn remove_breakpoint(&self, id: u32) -> Result<()> {
        unsafe {
            let bp = self.0
                .GetBreakpointById(id)
                .map_err(|e| DebugError::Com {
                    message: format!("GetBreakpointById: {}", e),
                })?;
            self.remove_breakpoint_internal(bp)
        }
    }

    pub fn list_breakpoints(&self) -> Result<Vec<models::BreakpointInfo>> {
        unsafe {
            let count = self.get_number_breakpoints()?;
            if count == 0 {
                return Ok(vec![]);
            }
            let mut params = vec![windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_PARAMETERS::default(); count as usize];
            self.0
                .GetBreakpointParameters(count, None, 0, params.as_mut_ptr())
                .map_err(|e| DebugError::Com {
                    message: format!("GetBreakpointParameters: {}", e),
                })?;

            let mut result = Vec::with_capacity(count as usize);
            for p in params {
                result.push(models::BreakpointInfo {
                    id: p.Id,
                    address: p.Offset,
                    enabled: (p.Flags & windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_ENABLED) != 0,
                    // CurrentPassCount is passes *remaining* before the next
                    // trigger, not a hit tally — surface both counts honestly
                    // rather than mislabeling the remaining count as hits.
                    pass_count: p.PassCount,
                    current_pass_count: p.CurrentPassCount,
                    flags: p.Flags,
                });
            }
            Ok(result)
        }
    }

    pub fn get_actual_processor_type(&self) -> Result<u32> {
        unsafe {
            self.0
                .GetActualProcessorType()
                .map_err(|e| DebugError::Com {
                    message: format!("GetActualProcessorType: {}", e),
                })
        }
    }

    pub fn get_stack_trace(
        &self,
        frame_offset: u64,
        stack_offset: u64,
        instruction_offset: u64,
        frames: &mut [windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STACK_FRAME],
    ) -> Result<u32> {
        unsafe {
            let mut filled: u32 = 0;
            self.0
                .GetStackTrace(
                    frame_offset,
                    stack_offset,
                    instruction_offset,
                    frames,
                    Some(&mut filled),
                )
                .map_err(|e| DebugError::Com {
                    message: format!("GetStackTrace: {}", e),
                })?;
            Ok(filled)
        }
    }
}
