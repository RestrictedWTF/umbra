use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "net:port=50000,key=12n8y0vrkqfqi.88k3uzpscmtq.z9c2333mz43n.2eonw3w2x2a7v".to_string());

    let session = debugger::DebugSession::create("kernel".to_string(), target.clone()).await?;

    println!("Attaching kernel target: {}...", target);
    session.attach_kernel(&target).await?;
    println!("Attached. Waiting a moment...");
    sleep(Duration::from_millis(500)).await;

    println!("Breaking...");
    session.break_execution().await?;
    sleep(Duration::from_millis(500)).await;

    println!("Getting registers...");
    match session.get_registers().await {
        Ok(regs) => println!("Got {} registers, arch={}", regs.registers.len(), regs.architecture),
        Err(e) => println!("get_registers error: {:#}", e),
    }

    println!("Getting stack trace...");
    match session.stack_trace(16).await {
        Ok(frames) => println!("Got {} frames", frames.len()),
        Err(e) => println!("stack_trace error: {:#}", e),
    }

    println!("Listing modules...");
    match session.list_modules().await {
        Ok(mods) => println!("Got {} modules", mods.len()),
        Err(e) => println!("list_modules error: {:#}", e),
    }

    println!("Listing drivers...");
    match session.list_drivers().await {
        Ok(drivers) => println!("Got {} drivers", drivers.len()),
        Err(e) => println!("list_drivers error: {:#}", e),
    }

    println!("Reading memory at RIP...");
    match session.read_memory(0xfffff8032a813f80, 32).await {
        Ok(mem) => println!("Read {} bytes: {}", mem.len(), mem.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        Err(e) => println!("read_memory error: {:#}", e),
    }

    println!("Disassembling at RIP...");
    match session.disassemble(0xfffff8032a813f80, Some(4)).await {
        Ok((insn, truncated)) => println!("Got {} instructions, truncated={}", insn.len(), truncated),
        Err(e) => println!("disassemble error: {:#}", e),
    }

    println!("Detaching...");
    session.detach().await?;
    println!("Done.");
    Ok(())
}
