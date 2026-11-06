//! Does the .env parser named in the spec return the value that was written?
use std::io::Cursor;

fn parse(text: &str) -> Result<Vec<(String, String)>, String> {
    dotenvy::from_read_iter(Cursor::new(text.as_bytes()))
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

fn main() {
    for input in [
        "JWT_SECRET=$abc123",
        "PW=pa$$word",
        "TOKEN=abc$def",
        "QUOTED='pa$$word'",
        "DOUBLE=\"pa$$word\"",
        "A=1\nB=$A",
        "HOME_LEAK=$HOME",
        "BAD LINE fake_SECRETVALUE=x y z",
        "KEY='fake_SECRETVALUE",
    ] {
        match parse(input) {
            Ok(v) => println!("{input:?}\n   -> {v:?}"),
            Err(e) => println!("{input:?}\n   -> ERROR: {e}"),
        }
    }
}
