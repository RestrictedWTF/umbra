#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: wait_repro <pid>")
        .parse()?;

    let session = debugger::DebugSession::create("process".to_string(), pid.to_string()).await?;

    println!("Attaching to PID {}...", pid);
    session.attach_process(pid).await?;
    println!("Attached. Getting registers (fresh attach)...");
    let regs = session.get_registers().await?;
    println!("Got {} registers, arch={}", regs.registers.len(), regs.architecture);

    println!("Waiting for event...");
    session.wait_for_event(5000).await?;
    println!("Wait returned. Getting registers...");
    let regs = session.get_registers().await?;
    println!("Got {} registers after wait, arch={}", regs.registers.len(), regs.architecture);

    println!("Detaching...");
    session.detach().await?;
    println!("Done.");
    Ok(())
}
