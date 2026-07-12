#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: bp_repro <pid>")
        .parse()?;

    let session = debugger::DebugSession::create("process".to_string(), pid.to_string()).await?;

    println!("Attaching to PID {}...", pid);
    session.attach_process(pid).await?;
    println!("Attached.");

    let regs = session.get_registers().await?;
    let rip = regs.registers.iter().find(|r| r.name == "rip").map(|r| u64::from_str_radix(&r.value[2..], 16)).transpose()?;
    println!("RIP = {:?}", rip);

    if let Some(addr) = rip {
        println!("Setting breakpoint at current RIP {:#x}...", addr);
        let bp = session.set_breakpoint(addr).await?;
        println!("Breakpoint set: id={} addr={:#x}", bp.id, bp.address);

        let list = session.list_breakpoints().await?;
        println!("Breakpoints listed: {}", list.len());

        println!("Removing breakpoint id={}...", bp.id);
        session.remove_breakpoint(bp.id).await?;
        println!("Breakpoint removed.");
    }

    println!("Detaching...");
    session.detach().await?;
    println!("Done.");
    Ok(())
}
