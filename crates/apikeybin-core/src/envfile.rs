//! A deliberately small `.env` reader, and the rules for injecting one into a child process.
//!
//! Why not an existing parser: API keys contain `$`. The commonly used crate expands it, so
//! `PW=pa$$word` became `pa`, `JWT_SECRET=$abc` became empty, and `X=$HOME` became the
//! sender's home directory, all silently. Its errors also print the offending line, which
//! holds the secret. Here nothing is ever expanded, and an error names only a line number.

use core::fmt;

use zeroize::Zeroizing;

/// Errors carry a line number and a reason, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    NotUtf8,
    MissingEquals { line: usize },
    BadName { line: usize },
    UnterminatedQuote { line: usize },
    TextAfterQuote { line: usize },
    DuplicateName { line: usize },
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvError::NotUtf8 => f.write_str("the file is not valid UTF-8"),
            EnvError::MissingEquals { line } => write!(f, "line {line}: expected NAME=value"),
            EnvError::BadName { line } => write!(f, "line {line}: invalid variable name"),
            EnvError::UnterminatedQuote { line } => write!(f, "line {line}: unterminated quote"),
            EnvError::TextAfterQuote { line } => write!(f, "line {line}: text after closing quote"),
            EnvError::DuplicateName { line } => write!(f, "line {line}: variable defined twice"),
        }
    }
}

impl std::error::Error for EnvError {}

/// One variable. Debug shows the name and hides the value.
pub struct EnvVar {
    pub name: String,
    pub value: Zeroizing<String>,
}

impl fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvVar")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .finish()
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Accepts `NAME=value`, `export NAME=value`, blank lines and `#` comments. A value in single
/// or double quotes is taken literally, without the quotes. An unquoted value is taken as
/// written up to ` #`, with surrounding spaces removed.
pub fn parse(bytes: &[u8]) -> Result<Vec<EnvVar>, EnvError> {
    let text = core::str::from_utf8(bytes).map_err(|_| EnvError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: Vec<EnvVar> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed
            .strip_prefix("export ")
            .map_or(trimmed, str::trim_start);
        let (name, rest) = body
            .split_once('=')
            .ok_or(EnvError::MissingEquals { line })?;
        let name = name.trim_end();
        if !valid_name(name) {
            return Err(EnvError::BadName { line });
        }
        if out.iter().any(|v| v.name == name) {
            return Err(EnvError::DuplicateName { line });
        }
        let value = read_value(rest.trim_start(), line)?;
        out.push(EnvVar {
            name: name.to_owned(),
            value: Zeroizing::new(value.to_owned()),
        });
    }
    Ok(out)
}

fn read_value(rest: &str, line: usize) -> Result<&str, EnvError> {
    for quote in ['"', '\''] {
        if let Some(inner) = rest.strip_prefix(quote) {
            let (value, after) = inner
                .split_once(quote)
                .ok_or(EnvError::UnterminatedQuote { line })?;
            let after = after.trim_start();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(EnvError::TextAfterQuote { line });
            }
            return Ok(value);
        }
    }
    Ok(rest
        .split_once(" #")
        .map_or(rest, |(value, _comment)| value)
        .trim_end())
}

/// Variables that change what a program does rather than what it is configured with. Setting
/// one is running the sender's code on this machine, so a compromised paired device must not
/// be able to do it just because the person answered yes to "receive a .env". This is a
/// denylist and so cannot be complete, which is why the variable names are also shown before
/// the child process starts.
pub fn is_code_execution_vector(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SHELL",
        "IFS",
        "ENV",
        "BASH_ENV",
        "ZDOTDIR",
        "CDPATH",
        "PS4",
        "PROMPT_COMMAND",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_REPL_EXTERNAL_MODULE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PERL5OPT",
        "PERL5LIB",
        "PERL5DB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "GEM_PATH",
        "GEM_HOME",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "CARGO_BUILD_RUSTC",
        "CARGO_HOME",
        "GOFLAGS",
        "GOPATH",
        "GOROOT",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "BROWSER",
        "SSH_ASKPASS",
        "SUDO_ASKPASS",
        "GIT_ASKPASS",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "WINDIR",
        "PSMODULEPATH",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "DOTNET_STARTUP_HOOKS",
        "DOTNET_ROOT",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER",
        "CORECLR_PROFILER_PATH",
        "COR_ENABLE_PROFILING",
        "COR_PROFILER",
        "COR_PROFILER_PATH",
    ];
    const PREFIX: &[&str] = &[
        "LD_",
        "DYLD_",
        "BASH_FUNC_",
        "GIT_",
        "NPM_CONFIG_",
        "YARN_",
        "PNPM_",
        "MAVEN_",
        "GRADLE_",
        "ELECTRON_",
        "NODE_V8_",
        "PYTHONDEV",
    ];
    let upper = name.to_ascii_uppercase();
    EXACT.contains(&upper.as_str()) || PREFIX.iter().any(|p| upper.starts_with(p))
}

/// The names `--exec` must refuse unless each is allowed explicitly on the command line.
pub fn blocked_names<'a>(vars: &'a [EnvVar], allowed: &[&str]) -> Vec<&'a str> {
    vars.iter()
        .filter(|v| is_code_execution_vector(&v.name) && !allowed.contains(&v.name.as_str()))
        .map(|v| v.name.as_str())
        .collect()
}
