//! attested-restore CLI: run the protocol demo or re-verify a trace file.

use std::path::PathBuf;

use attested_restore::demo::{self, DemoConfig};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "attested-restore",
    version,
    about = "Attested, rollback-resistant snapshot/restore for confidential VMs (research prototype)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run honest + adversarial trials and emit a trace dataset.
    Demo {
        /// Seed for deterministic synthetic guest state.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Write the trace JSON here (stdout if omitted).
        #[arg(long)]
        trace_out: Option<PathBuf>,
    },
    /// Deterministically replay a trace file and check every decision.
    Verify {
        /// Trace JSON produced by `demo`.
        #[arg(long)]
        trace: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Demo { seed, trace_out } => {
            eprintln!(
                "WARNING: this demo uses MockBackend with a compiled-in TEST key. \
                 Not for production use."
            );
            let cfg = DemoConfig {
                seed,
                state_sizes: vec![
                    1024,
                    64 * 1024,
                    1024 * 1024,
                    16 * 1024 * 1024,
                    64 * 1024 * 1024,
                ],
                base_time: 1_700_000_000,
            };
            let trace = demo::run_demo(&cfg);
            let json = serde_json::to_string_pretty(&trace).expect("serialize trace");
            match &trace_out {
                Some(p) => std::fs::write(p, &json).expect("write trace file"),
                None => println!("{json}"),
            }
            let (accepts, rejects) = trace.trials.iter().fold((0, 0), |(a, r), t| {
                if t.decision == "accept" {
                    (a + 1, r)
                } else {
                    (a, r + 1)
                }
            });
            eprintln!(
                "demo complete: {} trials ({} accept, {} reject)",
                trace.trials.len(),
                accepts,
                rejects
            );
        }
        Cmd::Verify { trace } => {
            let data = std::fs::read_to_string(&trace).expect("read trace file");
            let trace: demo::TraceFile = serde_json::from_str(&data).expect("parse trace file");
            let mismatches = demo::replay_trace(&trace);
            if mismatches == 0 {
                println!(
                    "OK: all {} trial decisions reproduced deterministically",
                    trace.trials.len()
                );
            } else {
                eprintln!("FAIL: {mismatches} decision mismatches");
                std::process::exit(1);
            }
        }
    }
}
