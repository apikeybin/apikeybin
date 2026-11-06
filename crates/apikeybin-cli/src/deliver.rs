//! Where the content goes. See docs/SPEC.md §8.3 and §9.3.

use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};

use apikeybin_core::{envfile, text};
use zeroize::Zeroizing;

use crate::{Failure, code};

/// A pipe or a file gets the exact bytes. A terminal gets text made safe, and nothing that is not text.
pub fn print(content: &[u8]) -> Result<(), Failure> {
    let mut stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    if terminal && (content.contains(&0) || std::str::from_utf8(content).is_err()) {
        return Err(Failure::new(
            code::FAILED,
            "this file is not text, so it is not shown on the screen",
        ));
    }
    if terminal {
        eprintln!("Note: this is printing to the screen. Use --out or --exec to avoid that.");
    }
    let (shown, changed) = for_terminal(content);
    let bytes = if terminal { shown.as_bytes() } else { content };
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|_| Failure::new(code::FAILED, "could not write to stdout"))?;
    if terminal && changed {
        eprintln!(
            "Note: the sender's text has characters that could control this terminal. They are shown as \\u{{...}}."
        );
    }
    Ok(())
}

/// The sender chooses this text and a terminal obeys what it receives: an escape sequence can move
/// the cursor, hide lines, or write to the clipboard. Reports whether anything had to change.
fn for_terminal(content: &[u8]) -> (Zeroizing<String>, bool) {
    let source = Zeroizing::new(String::from_utf8_lossy(content).into_owned());
    let mut shown = Zeroizing::new(String::with_capacity(source.len()));
    let mut changed = false;
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' || c == '\t' {
            shown.push(c);
        } else if c == '\r' && chars.peek() == Some(&'\n') {
            // A Windows line ending looks the same without it.
        } else if text::is_forbidden(c) {
            shown.push_str(&c.escape_unicode().to_string());
            changed = true;
        } else {
            shown.push(c);
        }
    }
    (shown, changed)
}

/// The read is spent and this is the only copy. At a terminal, offer a place to keep it.
pub fn rescue(content: &[u8], failure: Failure) -> Failure {
    let Failure(exit, message) = failure;
    eprintln!("apikeybin: {message}");
    let used = "the link has been used, so ask for a new one";
    if !std::io::stdin().is_terminal() {
        return Failure::new(exit, used);
    }
    for _ in 0..3 {
        eprint!("This is the only copy. Save it to this file (Enter to discard): ");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            break;
        }
        let path = line.trim();
        if path.is_empty() {
            break;
        }
        match write_file(Path::new(path), content, false, false) {
            Ok(()) => {
                return Failure::new(exit, format!("saved to {path}, for your user only"));
            }
            Err(Failure(_, why)) => eprintln!("apikeybin: {why}"),
        }
    }
    Failure::new(exit, used)
}

/// Is there something to run? Asked before the read is spent, so a typing mistake costs nothing.
#[cfg(unix)]
pub fn check_program(program: &str) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    let runnable = |path: &Path| {
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let found = if program.contains('/') {
        runnable(Path::new(program))
    } else {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|folder| runnable(&folder.join(program)))
        })
    };
    if found {
        Ok(())
    } else {
        Err(Failure::new(
            code::USAGE,
            format!("cannot find the command {program}. The link has not been used"),
        ))
    }
}

/// Finding programs on Windows comes with the rest of the Windows work in the spec (M3).
#[cfg(not(unix))]
pub fn check_program(_program: &str) -> Result<(), Failure> {
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf, Failure> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent = parent.canonicalize().map_err(|e| {
        Failure::new(
            code::REFUSED_PATH,
            format!("the folder cannot be used: {}", e.kind()),
        )
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| Failure::new(code::REFUSED_PATH, "that is not a file name"))?;
    Ok(parent.join(name))
}

/// A folder that syncs to someone's cloud. This is a heuristic: it knows the common places, and
/// it says so in the error. Compared by path component, so "MyOneDriveNotes" does not match.
pub fn synced_folder(path: &Path) -> Option<&'static str> {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    let has = |name: &str| parts.iter().any(|p| p == name);
    let has_prefix = |prefix: &str| parts.iter().any(|p| p.starts_with(prefix));
    let in_library = |name: &str| {
        parts
            .windows(2)
            .any(|w| matches!(w, [a, b] if a == "library" && b == name))
    };
    if in_library("mobile documents") {
        return Some("iCloud Drive");
    }
    if in_library("cloudstorage") {
        return Some("a cloud storage folder");
    }
    if has("dropbox") {
        return Some("Dropbox");
    }
    if has_prefix("onedrive") {
        return Some("OneDrive");
    }
    if has("google drive") || has("googledrive") {
        return Some("Google Drive");
    }
    if has("box sync") || has("pcloud drive") {
        return Some("a cloud storage folder");
    }
    None
}

/// Runs before the record is read, so a mistake here does not waste the one read.
pub fn check_out_path(path: &Path, force: bool, allow_synced: bool) -> Result<(), Failure> {
    let full = absolute(path)?;
    if !allow_synced && let Some(service) = synced_folder(&full) {
        return Err(Failure::new(
            code::REFUSED_PATH,
            format!(
                "that folder looks like it syncs to {service}. Use --allow-synced if you really want this"
            ),
        ));
    }
    if full.is_dir() {
        return Err(Failure::new(
            code::REFUSED_PATH,
            "that is a folder. Give the name of a file",
        ));
    }
    if !force && std::fs::symlink_metadata(&full).is_ok() {
        return Err(Failure::new(
            code::REFUSED_PATH,
            "that file exists. Use --force to replace it",
        ));
    }
    check_writable(full.parent().unwrap_or(Path::new(".")))
}

/// Asked before the read is spent, because afterwards the content has nowhere else to go.
fn check_writable(folder: &Path) -> Result<(), Failure> {
    let suffix =
        apikeybin_core::link::random_hex().map_err(|e| Failure::new(code::FAILED, e.to_string()))?;
    let probe = folder.join(format!(".apikeybin-check-{suffix}"));
    create_exclusive(&probe, b"")
        .and_then(|()| std::fs::remove_file(&probe))
        .map_err(|e| {
            Failure::new(
                code::REFUSED_PATH,
                format!("cannot write in that folder: {}", e.kind()),
            )
        })
}

#[cfg(unix)]
fn owner_only(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only(_options: &mut std::fs::OpenOptions) {
    // Windows permissions come from the keystore work in the spec (M3): not done yet.
}

fn create_exclusive(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    owner_only(&mut options);
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()
}

/// Without --force, a single exclusive create: it does not follow a symlink and cannot overwrite.
/// With --force, write beside it and rename: a symlink at the path gets replaced, not followed.
pub fn write_file(
    path: &Path,
    content: &[u8],
    force: bool,
    allow_synced: bool,
) -> Result<(), Failure> {
    check_out_path(path, force, allow_synced)?;
    let full = absolute(path)?;
    if !force {
        return create_exclusive(&full, content).map_err(|e| {
            Failure::new(
                code::REFUSED_PATH,
                format!("could not write the file: {}", e.kind()),
            )
        });
    }
    let suffix =
        apikeybin_core::link::random_hex().map_err(|e| Failure::new(code::FAILED, e.to_string()))?;
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = full.with_file_name(format!(".{name}.{suffix}.tmp"));
    let result = create_exclusive(&temp, content).and_then(|()| std::fs::rename(&temp, &full));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|e| {
        Failure::new(
            code::REFUSED_PATH,
            format!("could not write the file: {}", e.kind()),
        )
    })
}

/// Reads the content as a .env file and runs the command with it. On Unix this replaces this
/// process, so nothing of ours stays around holding the values, and signals go straight to it.
pub fn exec(content: &[u8], allowed: &[String], command: &[String]) -> Result<(), Failure> {
    let vars = envfile::parse(content)
        .map_err(|e| Failure::new(code::FAILED, format!("not a .env file: {e}")))?;
    let allowed: Vec<&str> = allowed.iter().map(String::as_str).collect();
    let blocked = envfile::blocked_names(&vars, &allowed);
    if !blocked.is_empty() {
        return Err(Failure::new(
            code::BLOCKED_VARIABLE,
            format!(
                "refusing to run: {} can change what the command executes. If you trust the sender, allow each with --allow-env",
                blocked.join(", ")
            ),
        ));
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Failure::new(code::USAGE, "--exec needs a command after --"))?;
    let names: Vec<&str> = vars.iter().map(|v| v.name.as_str()).collect();
    eprintln!("Setting {} variables: {}", names.len(), names.join(", "));

    let mut child = std::process::Command::new(program);
    child.args(args);
    for var in &vars {
        child.env(&var.name, var.value.as_str());
    }
    run(child, program)
}

#[cfg(unix)]
fn run(mut child: std::process::Command, program: &str) -> Result<(), Failure> {
    use std::os::unix::process::CommandExt;
    let error = child.exec();
    Err(Failure::new(
        code::FAILED,
        format!("could not run {program}: {}", error.kind()),
    ))
}

#[cfg(not(unix))]
fn run(mut child: std::process::Command, program: &str) -> Result<(), Failure> {
    let status = child.status().map_err(|e| {
        Failure::new(
            code::FAILED,
            format!("could not run {program}: {}", e.kind()),
        )
    })?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "apikeybin-deliver-{name}-{}",
            apikeybin_core::link::random_hex().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_terminal_gets_escapes_as_text_and_ordinary_text_unchanged() {
        let (shown, changed) = for_terminal(b"KEY=abc $x\n\tNEXT=\xe6\x97\xa5\xe6\x9c\xac\r\n");
        assert_eq!(shown.as_str(), "KEY=abc $x\n\tNEXT=日本\n");
        assert!(!changed);
        let (shown, changed) = for_terminal(b"a\x1b]52;c;eA==\x07b\rc");
        assert_eq!(shown.as_str(), "a\\u{1b}]52;c;eA==\\u{7}b\\u{d}c");
        assert!(changed);
        let (shown, changed) = for_terminal("a\u{202e}b\u{9b}c".as_bytes());
        assert_eq!(shown.as_str(), "a\\u{202e}b\\u{9b}c");
        assert!(changed);
        let (shown, _) = for_terminal(b"a\xffb");
        assert_eq!(shown.as_str(), "a\u{fffd}b");
    }

    #[test]
    fn the_exclusive_create_never_touches_what_is_already_there() {
        let dir = temp_dir("exclusive");
        let path = dir.join("existing");
        std::fs::write(&path, "keep").unwrap();
        assert!(create_exclusive(&path, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
        let fresh = dir.join("fresh");
        create_exclusive(&fresh, b"new").unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_exclusive_create_does_not_follow_a_symlink() {
        let dir = temp_dir("symlink");
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_exclusive(&link, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // Dangling too: a create that followed it would make a file somewhere else.
        let elsewhere = dir.join("elsewhere");
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(&elsewhere, &dangling).unwrap();
        assert!(create_exclusive(&dangling, b"new").is_err());
        assert!(!elsewhere.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn synced_folders_match_by_whole_path_component() {
        for (path, service) in [
            (
                "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/x",
                Some("iCloud Drive"),
            ),
            (
                "/Users/a/Library/CloudStorage/GoogleDrive-a/x",
                Some("a cloud storage folder"),
            ),
            ("/Users/a/Dropbox/x", Some("Dropbox")),
            ("/Users/a/OneDrive - Company/x", Some("OneDrive")),
            ("/Users/a/Google Drive/x", Some("Google Drive")),
            ("/Users/a/projects/x", None),
            ("/Users/a/my-dropbox-notes/x", None),
            ("/Users/a/Library/Caches/x", None),
        ] {
            assert_eq!(synced_folder(Path::new(path)), service, "{path}");
        }
    }
}
