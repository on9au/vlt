use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use vlt::{crypto::RecoveryKey, header::KdfParams, vault::Vault};
use zeroize::Zeroizing;

const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Parser)]
#[command(version, about = "Local encrypted vault (M1: keyslots only)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault and print its recovery key (shown once)
    Init {
        path: PathBuf,
        /// Argon2id memory in MiB
        #[arg(long, default_value_t = 256)]
        kdf_mib: u32,
        /// Argon2id passes
        #[arg(long, default_value_t = 3)]
        kdf_iters: u32,
    },
    /// Check the password opens the vault (and time the KDF)
    Unlock { path: PathBuf },
    /// Change the password (asks for the current one)
    Passwd { path: PathBuf },
    /// Forgot the password: use the recovery key to set a new one
    Recover { path: PathBuf },
    /// Replace the recovery key; the old one stops working
    RotateRecovery { path: PathBuf },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Init {
            path,
            kdf_mib,
            kdf_iters,
        } => {
            let kdf = KdfParams {
                mem_cost_kib: kdf_mib.checked_mul(1024).ok_or("--kdf-mib too large")?,
                time_cost: kdf_iters,
                parallelism_cost: 1,
            };
            let pw = new_password()?;
            let started = Instant::now();
            let (v, rk) = Vault::init(&path, pw.as_bytes(), kdf)?;
            eprintln!(
                "created {} (id {})",
                v.path().display(),
                hex::encode(v.vault_id())
            );
            eprintln!(
                "KDF took {:?} (aim for ~1s; adjust --kdf-mib / --kdf-iters)",
                started.elapsed()
            );
            show_recovery_key(&rk);
        }
        Cmd::Unlock { path } => {
            let pw = prompt("Password: ")?;
            let started = Instant::now();
            let v = Vault::unlock(&path, pw.as_bytes())?;
            eprintln!(
                "unlocked {} in {:?}",
                hex::encode(v.vault_id()),
                started.elapsed()
            );
        }
        Cmd::Passwd { path } => {
            let old = prompt("Current password: ")?;
            let new = new_password()?;
            Vault::change_password(&path, old.as_bytes(), new.as_bytes())?;
            eprintln!("password changed");
        }
        Cmd::Recover { path } => {
            let rk = RecoveryKey::parse(&prompt("Recovery key: ")?)?;
            let new = new_password()?;
            Vault::recover(&path, &rk, new.as_bytes())?;
            eprintln!(
                "password reset. Your recovery key is unchanged; run rotate-recovery if it may have leaked."
            );
        }
        Cmd::RotateRecovery { path } => {
            let pw = prompt("Password: ")?;
            let (_v, rk) = Vault::rotate_recovery(&path, pw.as_bytes())?;
            eprintln!("old recovery key no longer works");
            show_recovery_key(&rk);
        }
    }
    Ok(())
}

fn prompt(msg: &str) -> std::io::Result<Zeroizing<String>> {
    rpassword::prompt_password(msg).map(Zeroizing::new)
}

fn new_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let pw = prompt("New password: ")?;
    if pw.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("password must be at least {MIN_PASSWORD_CHARS} characters").into());
    }
    if *prompt("Confirm password: ")? != *pw {
        return Err("passwords don't match".into());
    }
    Ok(pw)
}

fn show_recovery_key(rk: &RecoveryKey) {
    eprintln!();
    eprintln!("RECOVERY KEY (shown once, write it down and put it somewhere safe):");
    println!("{}", *rk.reveal());
    eprintln!();
}
