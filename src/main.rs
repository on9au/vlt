use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use vlt::{
    crypto::RecoveryKey,
    header::{KdfParams, SlotId},
    manifest::{self, Listing},
    ops::{self, SlotRef},
    slot::Credential,
    store::{self, Store},
    vault::{LockedVault, Vault},
};
use zeroize::Zeroizing;

const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Parser)]
#[command(version, about = "Local encrypted file vault")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault directory and print its recovery key (shown once)
    Init {
        vault: PathBuf,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Encrypt a file into the vault
    Add {
        vault: PathBuf,
        file: PathBuf,
        /// Path inside the vault [default: the file's name]
        #[arg(long = "as")]
        dest: Option<String>,
        /// Overwrite a file already at that path
        #[arg(long)]
        replace: bool,
    },
    /// List a directory in the vault [default: the root]
    Ls { vault: PathBuf, dir: Option<String> },
    /// Decrypt a file out of the vault
    Get {
        vault: PathBuf,
        path: String,
        /// Where to write it (`-` for stdout) [default: its name, in the
        /// current directory]. Never overwrites.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Remove a file from the vault
    Rm { vault: PathBuf, path: String },
    /// Check the password opens the vault (and time the KDF)
    Unlock { vault: PathBuf },
    /// Change the password (asks for the current one)
    Passwd { vault: PathBuf },
    /// Forgot a password: use the recovery key to set a new one
    ///
    /// --kdf-mib/--kdf-iters only apply if the vault has no password slot left
    /// to reset; otherwise the slot keeps its own KDF params.
    Recover {
        vault: PathBuf,
        /// Which password slot to reset, by id or label. Required only if
        /// the vault has more than one.
        #[arg(long)]
        slot: Option<String>,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Replace the recovery key; the old one stops working
    RotateRecovery { vault: PathBuf },
}

#[derive(clap::Args)]
struct KdfArgs {
    /// Argon2id memory in MiB
    #[arg(long, default_value_t = 256)]
    kdf_mib: u32,
    /// Argon2id passes
    #[arg(long, default_value_t = 3)]
    kdf_iters: u32,
}

impl KdfArgs {
    fn params(&self) -> Result<KdfParams, &'static str> {
        Ok(KdfParams {
            mem_cost_kib: self
                .kdf_mib
                .checked_mul(1024)
                .ok_or("--kdf-mib too large")?,
            time_cost: self.kdf_iters,
            parallelism_cost: 1,
        })
    }
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
        Cmd::Init { vault, kdf } => {
            let kdf = kdf.params()?;
            let pw = new_password()?;
            let started = Instant::now();
            let (s, rk) = store::init(&vault, pw.as_bytes(), kdf)?;
            eprintln!(
                "created {} (id {})",
                s.root().display(),
                hex::encode(s.vault().id())
            );
            eprintln!(
                "KDF took {:?} (aim for ~1s; adjust --kdf-mib / --kdf-iters)",
                started.elapsed()
            );
            show_recovery_key(&rk);
        }
        Cmd::Add {
            vault,
            file,
            dest,
            replace,
        } => {
            let dest = match dest {
                Some(d) => d,
                None => file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("can't use that file name in the vault; pass --as")?
                    .to_owned(),
            };
            let src = BufReader::new(File::open(&file)?);
            let mut s = open_store(&vault)?;
            let size = s.add(&dest, src, replace)?;
            eprintln!("added {dest} ({size} bytes)");
        }
        Cmd::Ls { vault, dir } => {
            let s = open_store(&vault)?;
            for item in s.list(dir.as_deref().unwrap_or(""))? {
                match item {
                    Listing::Dir { name } => println!("{:>12}  {name}/", ""),
                    Listing::File { name, size } => println!("{size:>12}  {name}"),
                }
            }
        }
        Cmd::Get {
            vault,
            path,
            output,
        } => {
            // Validated first, so the default name can't be `..` or similar.
            let path = manifest::file_path(&path)?;
            let output = match output {
                Some(o) => o,
                None => PathBuf::from(path.rsplit('/').next().expect("non-empty")),
            };
            let s = open_store(&vault)?;
            if output == Path::new("-") {
                // Can't take back what's already been written to a pipe: on
                // error, the output so far is incomplete.
                let mut out = std::io::stdout().lock();
                s.get(&path, &mut out)?;
                out.flush()?;
            } else {
                let size = s.get_to_file(&path, &output)?;
                eprintln!("wrote {} ({size} bytes)", output.display());
            }
        }
        Cmd::Rm { vault, path } => {
            let mut s = open_store(&vault)?;
            s.remove(&path)?;
            eprintln!("removed {path}");
        }
        Cmd::Unlock { vault } => {
            let started = Instant::now();
            let v = unlock(&vault)?;
            eprintln!(
                "unlocked {} in {:?}",
                hex::encode(v.id()),
                started.elapsed()
            );
        }
        Cmd::Passwd { vault } => {
            let locked = LockedVault::read(store::header_path(&vault))?;
            let old = prompt("Current password: ")?;
            let mut v = locked.unlock(&Credential::Password(old.as_bytes()))?;
            // Only after the old password checked out.
            let new = new_password()?;
            let id = v.opened_by().expect("unlocked by a slot");
            ops::set_password(&mut v, id, new.as_bytes())?;
            eprintln!("password changed");
        }
        Cmd::Recover { vault, slot, kdf } => {
            let kdf = kdf.params()?;
            // A number is an id; anything else is a label.
            let choice = slot.as_deref().map(|s| match s.parse() {
                Ok(n) => SlotRef::Id(SlotId(n)),
                Err(_) => SlotRef::Label(s),
            });
            let locked = LockedVault::read(store::header_path(&vault))?;
            let rk = RecoveryKey::parse(&prompt("Recovery key: ")?)?;
            let mut v = locked.unlock(&Credential::Recovery(&rk))?;
            // Settle the slot before asking for a new password, so a missing
            // --slot doesn't waste the typing.
            let target = ops::choose_password_slot(&v, choice)?;
            let new = new_password()?;
            let started = Instant::now();
            match target {
                Some(id) => ops::set_password(&mut v, id, new.as_bytes())?,
                None => {
                    ops::add_password(&mut v, new.as_bytes(), kdf, None)?;
                }
            }
            eprintln!("KDF took {:?}", started.elapsed());
            eprintln!(
                "password reset. Your recovery key is unchanged; run rotate-recovery if it may have leaked."
            );
        }
        Cmd::RotateRecovery { vault } => {
            let mut v = unlock(&vault)?;
            let rk = ops::rotate_recovery(&mut v)?;
            eprintln!("old recovery key no longer works");
            show_recovery_key(&rk);
        }
    }
    Ok(())
}

/// Read the header first, so a wrong path fails before the password prompt.
fn unlock(vault: &Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let locked = LockedVault::read(store::header_path(vault))?;
    let pw = prompt("Password: ")?;
    Ok(locked.unlock(&Credential::Password(pw.as_bytes()))?)
}

fn open_store(vault: &Path) -> Result<Store, Box<dyn std::error::Error>> {
    Ok(Store::open(vault, unlock(vault)?)?)
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
