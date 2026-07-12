use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: interrupt_repro <pid>")
        .parse()?;

    let session = debugger::DebugSession::create("process".to_string(), pid.to_string()).await?;

    println!("Attaching to PID {}...", pid);
    session.attach_process(pid).await?;
    println!("Attached. Getting registers (fresh attach)...");
    let regs = session.get_registers().await?;
    println!("Got {} registers, arch={}", regs.registers.len(), regs.architecture);

    println!("Resuming...");
    session.resume().await?;
    sleep(Duration::from_millis(500)).await;

    println!("Breaking via SetInterrupt...");
    session.break_execution().await?;
    sleep(Duration::from_millis(500)).await;

    println!("Getting registers after resume+interrupt break...");
    let regs = session.get_registers().await?;
    println!("Got {} registers after interrupt, arch={}", regs.registers.len(), regs.architecture);

    println!("Detaching...");
    session.detach().await?;
    println!("Done.");
    Ok(())
}
