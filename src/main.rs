use std::{fs, path::PathBuf, process::ExitCode};

use clap::{error::ErrorKind, Parser, Subcommand};
use noisebench::{report::render_terminal, run_suite, verdict::audit_path, SuiteReport};
use serde::Serialize;

const EX_USAGE: u8 = 64;
const EX_SOFTWARE: u8 = 70;

#[derive(Debug, Parser)]
#[command(
    name = "noisebench",
    version,
    about = "Audit repeated-use privacy claims against a frozen longitudinal attacker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit one content-addressed trace dataset.
    Audit {
        dataset: PathBuf,
        /// Write the full machine-readable report.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Run the four pinned reference outcomes.
    Suite {
        fixtures: PathBuf,
        /// Write the full machine-readable suite report.
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                0
            } else {
                EX_USAGE
            };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("noisebench: {error}");
            ExitCode::from(EX_SOFTWARE)
        }
    }
}

fn execute(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Audit { dataset, json } => {
            let report = audit_path(&dataset).map_err(|error| error.to_string())?;
            if let Some(path) = json {
                write_json(&path, &report)?;
            }
            println!("{}", render_terminal(&report));
            Ok(report.exit_code)
        }
        Command::Suite { fixtures, json } => {
            let report = run_suite(&fixtures).map_err(|error| error.to_string())?;
            if let Some(path) = json {
                write_json(&path, &report)?;
            }
            print_suite(&report);
            if report.matches_all_expected() {
                Ok(0)
            } else {
                Err("one or more fixture outcomes did not match their pins".into())
            }
        }
    }
}

fn print_suite(report: &SuiteReport) {
    for entry in &report.entries {
        println!(
            "{}: {} ({}) [{}]",
            entry.fixture,
            entry.verdict.as_str(),
            entry.primary_reason_code.as_str(),
            if entry.expected_match {
                "match"
            } else {
                "mismatch"
            }
        );
    }
    let matched = report
        .entries
        .iter()
        .filter(|entry| entry.expected_match)
        .count();
    println!("{matched}/4 expected outcomes matched");
}

fn write_json(path: &PathBuf, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "JSON output path must name a file".to_owned())?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}
