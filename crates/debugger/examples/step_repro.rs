use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: step_repro <pid>")
        .parse()?;

    let session = debugger::DebugSession::create("process".to_string(), pid.to_string()).await?;

    println!("Attaching to PID {}...", pid);
    session.attach_process(pid).await?;
    println!("Attached. Getting registers (fresh attach)...");
    let regs = session.get_registers().await?;
    println!("Got {} registers, arch={}", regs.registers.len(), regs.architecture);

    println!("Stepping...");
    session.step().await?;
    println!("Step returned. Getting registers after step...");
    let regs = session.get_registers().await?;
    println!("Got {} registers after step, arch={}", regs.registers.len(), regs.architecture);

    println!("Resuming...");
    session.resume().await?;
    sleep(Duration::from_millis(500)).await;
    let events = session.poll_events().await?;
    println!("Events after resume: {:?}", events);

    println!("Breaking...");
    session.break_execution().await?;
    sleep(Duration::from_millis(500)).await;
    let events = session.poll_events().await?;
    println!("Events after break: {:?}", events);

    println!("Getting registers after resume+break...");
    let regs = session.get_registers().await?;
    println!("Got {} registers after resume+break, arch={}", regs.registers.len(), regs.architecture);

    println!("Stepping again...");
    session.step().await?;
    println!("Getting registers after second step...");
    let regs = session.get_registers().await?;
    println!("Got {} registers after second step, arch={}", regs.registers.len(), regs.architecture);

    println!("Detaching...");
    session.detach().await?;
    println!("Done.");
    Ok(())
}
