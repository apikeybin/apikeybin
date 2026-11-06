//! `apikeybin link` makes a link. `apikeybin open` reads one, without trusting any JavaScript from the
//! server: the decryption runs here. Same format as the browser version (docs/SPEC.md §19).
//!
//! stdout carries only what was asked for (the link, or the content). Everything else is stderr,
//! and nothing printed anywhere contains a secret.

mod deliver;
mod http;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use apikeybin_core::link;
use zeroize::Zeroizing;

const DEFAULT_SERVER: &str = "https://app.apikeybin.com";

/// Exit codes. Scripts can tell these apart.
pub mod code {
    pub const FAILED: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const GONE: u8 = 20;
    pub const WRONG_PASSPHRASE: u8 = 21;
    pub const BLOCKED_VARIABLE: u8 = 22;
    pub const REFUSED_PATH: u8 = 23;
}

#[derive(Parser)]
#[command(
    name = "apikeybin",
    version,
    about = "Hand over an API key with a link that opens once."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt text on this machine and print a link that opens once
    Link {
        /// File to send, or - for stdin
        input: PathBuf,
        /// How long an unopened link lives: 10m, 1h, 1d or 7d
        #[arg(long, default_value = "1d")]
        ttl: String,
        /// Also require a passphrase, which you tell the other person separately
        #[arg(long)]
        passphrase: bool,
        /// Do not send the file's name. It travels encrypted, inside the content
        #[arg(long)]
        no_name: bool,
        /// Server to use
        #[arg(long, default_value = DEFAULT_SERVER)]
        server: String,
    },
    /// Read a link. Reading uses it up
    Open {
        /// The link. Leave this out to paste it at a hidden prompt, which keeps it out of your
        /// shell history
        link: Option<String>,
        /// Write to this file with owner-only permissions, instead of printing
        #[arg(long, conflicts_with = "exec")]
        out: Option<PathBuf>,
        /// Replace the file if it exists
        #[arg(long, requires = "out")]
        force: bool,
        /// Allow writing inside a folder that syncs to the cloud
        #[arg(long, requires = "out")]
        allow_synced: bool,
        /// Read the content as a .env file and run a command with those variables
        #[arg(long, requires = "command")]
        exec: bool,
        /// Let this variable through --exec even though it can change what the command runs
        #[arg(long = "allow-env", value_name = "NAME", requires = "exec")]
        allow_env: Vec<String>,
        /// The command for --exec
        #[arg(last = true, value_name = "COMMAND", requires = "exec")]
        command: Vec<String>,
    },
}

/// A failure with its exit code. The message never includes a secret.
#[derive(Debug)]
pub struct Failure(pub u8, pub String);

impl Failure {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self(code, message.into())
    }
}

fn ttl_seconds(text: &str) -> Result<u32, Failure> {
    match text {
        "10m" => Ok(600),
        "1h" => Ok(3600),
        "1d" => Ok(86400),
        "7d" => Ok(604800),
        _ => Err(Failure::new(code::USAGE, "--ttl must be 10m, 1h, 1d or 7d")),
    }
}

/// One line that must stay off the screen. At a terminal it is a hidden prompt. In a pipe it is
/// the next line of stdin, so scripts and tests can supply it.
fn secret_line(prompt: &str) -> Result<Zeroizing<String>, Failure> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|_| Failure::new(code::FAILED, "could not read from the terminal"))
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|_| Failure::new(code::FAILED, "could not read from stdin"))?;
        let trimmed = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
        Ok(trimmed)
    }
}

fn run_link(
    input: &std::path::Path,
    ttl: &str,
    ask_passphrase: bool,
    no_name: bool,
    server: &str,
) -> Result<(), Failure> {
    let ttl = ttl_seconds(ttl)?;
    let origin = server.trim_end_matches('/');
    http::check_origin(origin)?;

    let name = if no_name || input.as_os_str() == "-" {
        None
    } else {
        input.file_name().map(|n| n.to_string_lossy().into_owned())
    };
    if let Some(name) = &name
        && !link::valid_name(name)
    {
        return Err(Failure::new(
            code::USAGE,
            "that file name cannot be sent. Rename the file, or use --no-name",
        ));
    }

    let mut bytes = Zeroizing::new(Vec::new());
    if input.as_os_str() == "-" {
        if ask_passphrase {
            return Err(Failure::new(
                code::USAGE,
                "--passphrase needs a file, because stdin cannot carry both",
            ));
        }
        std::io::stdin()
            .take(link::MAX_TEXT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::new(code::FAILED, "could not read stdin"))?;
    } else {
        let file = std::fs::File::open(input).map_err(|e| {
            Failure::new(
                code::FAILED,
                format!("could not open the file: {}", e.kind()),
            )
        })?;
        file.take(link::MAX_TEXT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                Failure::new(
                    code::FAILED,
                    format!("could not read the file: {}", e.kind()),
                )
            })?;
    }
    if bytes.is_empty() {
        return Err(Failure::new(code::USAGE, "nothing to send"));
    }
    if bytes.len() > link::MAX_TEXT {
        return Err(Failure::new(
            code::USAGE,
            format!("too large: the limit is {} bytes", link::MAX_TEXT),
        ));
    }

    let passphrase = if ask_passphrase {
        let first = secret_line("Passphrase: ")?;
        if first.is_empty() {
            return Err(Failure::new(code::USAGE, "the passphrase is empty"));
        }
        // A typing mistake here would make the link unreadable, and nobody could tell why.
        if std::io::stdin().is_terminal() && secret_line("Again: ")?.as_str() != first.as_str() {
            return Err(Failure::new(
                code::USAGE,
                "the two passphrases are different",
            ));
        }
        Some(first)
    } else {
        None
    };

    let (sealed, secret) = link::seal(
        &bytes,
        name.as_deref(),
        passphrase.as_ref().map(|p| p.as_str()),
        ttl,
    )
    .map_err(|e| Failure::new(code::USAGE, e.to_string()))?;
    let id = http::create(origin, &sealed)?;
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "{origin}/s/{id}#{}",
        link::fragment(&secret, passphrase.is_some())
    )
    .map_err(|_| Failure::new(code::FAILED, "could not write the link"))?;
    if passphrase.is_some() {
        eprintln!("Tell the other person the passphrase some other way than the link.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_open(
    given: Option<String>,
    out: Option<PathBuf>,
    force: bool,
    allow_synced: bool,
    exec: bool,
    allow_env: &[String],
    command: &[String],
) -> Result<(), Failure> {
    let text = match given {
        Some(text) => {
            eprintln!(
                "Note: a link given as an argument stays in your shell history until it is used."
            );
            Zeroizing::new(text)
        }
        None => secret_line("Paste the link: ")?,
    };
    let parsed = link::parse(&text)
        .map_err(|_| Failure::new(code::USAGE, "that is not a complete apikeybin link"))?;
    drop(text);
    http::check_origin(&parsed.origin)?;

    // Check what can be checked before the one read is spent.
    if let Some(path) = &out {
        deliver::check_out_path(path, force, allow_synced)?;
    }
    if exec && let Some(program) = command.first() {
        deliver::check_program(program)?;
    }
    let passphrase = if parsed.needs_passphrase {
        let given = secret_line("Passphrase: ")?;
        if given.is_empty() {
            return Err(Failure::new(
                code::USAGE,
                "no passphrase given. The link has not been used",
            ));
        }
        Some(given)
    } else {
        None
    };

    let record = http::open(&parsed)?;
    let opened = decrypt(&record, &parsed, passphrase)?;

    // The sender's name is only ever shown. Writing under it would let them choose .zshenv.
    if !exec && let Some(name) = &opened.name {
        eprintln!("The sender named this file {name}.");
    }
    let delivered = if exec {
        deliver::exec(&opened.content, allow_env, command)
    } else if let Some(path) = out {
        deliver::write_file(&path, &opened.content, force, allow_synced)
    } else {
        deliver::print(&opened.content)
    };
    delivered.map_err(|failure| deliver::rescue(&opened.content, failure))
}

/// The record is gone from the server by now, so a mistyped passphrase gets retries here.
fn decrypt(
    record: &link::Record,
    parsed: &link::ParsedLink,
    first_try: Option<Zeroizing<String>>,
) -> Result<link::Opened, Failure> {
    if record.pw != parsed.needs_passphrase {
        return Err(Failure::new(
            code::FAILED,
            "the link and the record disagree about the passphrase",
        ));
    }
    let Some(mut passphrase) = first_try else {
        return link::open(record, &parsed.secret, None)
            .map_err(|_| Failure::new(code::FAILED, "could not decrypt: the record is damaged"));
    };
    for attempt in 1..=3 {
        match link::open(record, &parsed.secret, Some(passphrase.as_str())) {
            Ok(content) => return Ok(content),
            Err(_) if attempt < 3 => {
                eprintln!("That passphrase did not work. Try again.");
                passphrase = secret_line("Passphrase: ")?;
            }
            Err(_) => {}
        }
    }
    Err(Failure::new(
        code::WRONG_PASSPHRASE,
        "wrong passphrase. The link has been used, so ask for a new one",
    ))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Link {
            input,
            ttl,
            passphrase,
            no_name,
            server,
        } => run_link(&input, &ttl, passphrase, no_name, &server),
        Command::Open {
            link,
            out,
            force,
            allow_synced,
            exec,
            allow_env,
            command,
        } => run_open(link, out, force, allow_synced, exec, &allow_env, &command),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(code, message)) => {
            eprintln!("apikeybin: {message}");
            ExitCode::from(code)
        }
    }
}
