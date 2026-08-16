use clap::Parser;

use blockscan::cli::Cli;
use blockscan::{init_tracing, run};

#[tokio::main]
async fn main() {
    // Load .env if present (ignore if absent).
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();
    init_tracing(cli.global.verbose);

    // `watch` mode stops on Ctrl-C; other subcommands ignore this future.
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    if let Err(e) = run(cli, shutdown).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
