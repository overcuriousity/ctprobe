use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ctprobe", about = "Certificate Transparency measurement service")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the collector and web server.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the nightly job once for a finished UTC day (default: yesterday).
    Nightly {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        day: Option<chrono::NaiveDate>,
        /// Allow the current day. Only safe on a stopped or copied data directory.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ctprobe=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { config } => {
            let cfg = ctprobe::config::Config::load(&config)?;
            let bind = cfg.bind;
            let data = cfg.data_dir.clone();
            let p = ctprobe::pipeline::Pipeline::start(cfg, Default::default()).await?;
            tracing::info!("collecting from {} logs", p.handle.registry.logs().len());
            let engine = std::sync::Arc::new(ctprobe::query::QueryEngine::open(&data)?);
            let state = ctprobe::web::AppState::new(engine, p.handle.clone());
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!("web interface on {bind}");
            tokio::spawn(ctprobe::web::serve(listener, state));
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = term.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tick.tick() => if p.is_finished() { break },
                }
            }
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
            p.shutdown().await?;
        }
        Cmd::Nightly { config, day, force } => {
            let cfg = ctprobe::config::Config::load(&config)?;
            let today = chrono::Utc::now().date_naive();
            let day = day.unwrap_or(today - chrono::Days::new(1));
            anyhow::ensure!(force || day < today, "{day} is not finished; compacting it would hide later rows");
            ctprobe::nightly::run_nightly(&cfg, day).await?;
        }
    }
    Ok(())
}
