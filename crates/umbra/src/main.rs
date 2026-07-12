use rmcp::{ServiceExt, transport::stdio};
use umbra::server::DebugMcpServer;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    // COM is initialized per-session on each session's dedicated engine thread
    // (see DebugSession::create). The main/tokio threads perform no COM work, so
    // there is deliberately no CoInitializeEx here.

    let server = DebugMcpServer::new();
    let session_manager = Arc::clone(&server.session_manager);
    let ttd_manager = Arc::clone(&server.ttd_manager);

    let service = server.serve(stdio()).await?;

    // Ctrl-C handler. The normal stdin-EOF path below also cleans up, so a clean
    // client disconnect no longer relies on receiving a signal.
    {
        let sm = Arc::clone(&session_manager);
        let tm = Arc::clone(&ttd_manager);
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("Ctrl-C signal error: {}", e);
                return;
            }
            tracing::info!("Ctrl-C received; detaching sessions and closing traces...");
            if let Err(e) = sm.destroy_all().await {
                tracing::error!("Error during shutdown: {}", e);
            }
            tm.close_all().await;
            std::process::exit(0);
        });
    }

    // Normal shutdown: the MCP client closed stdin and `waiting()` returned.
    // Previously this path skipped cleanup, leaking engine threads and leaving
    // ETW traces running; run the same teardown as the Ctrl-C path.
    let wait_result = service.waiting().await;
    tracing::info!("stdin closed; detaching sessions and closing traces...");
    if let Err(e) = session_manager.destroy_all().await {
        tracing::error!("Error during shutdown: {}", e);
    }
    ttd_manager.close_all().await;
    wait_result?;
    Ok(())
}
