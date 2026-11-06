//! The two API calls. Redirects are refused: following one would carry the token elsewhere.

use std::time::Duration;

use apikeybin_core::link;
use ureq::Agent;

use crate::{Failure, code};

/// The whole reply is small: a padded record is at most about 88 KiB in base64.
const MAX_REPLY: u64 = 96 * 1024;

/// HTTPS, or plain HTTP only on this machine, which is what the tests use.
pub fn check_origin(origin: &str) -> Result<(), Failure> {
    if link::allowed_origin(origin) {
        Ok(())
    } else {
        Err(Failure::new(code::USAGE, "the server must use https"))
    }
}

fn agent() -> Agent {
    Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Returns the status and body of a POST, with a size limit on what it will read.
fn post(url: &str, body: &str) -> Result<(u16, String), Failure> {
    let mut response = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Apikeybin", "1")
        .send(body)
        .map_err(|_| Failure::new(code::FAILED, "could not reach the server"))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_REPLY)
        .read_to_string()
        .map_err(|_| Failure::new(code::FAILED, "the server sent an unreadable reply"))?;
    Ok((status, text))
}

pub fn create(origin: &str, sealed: &link::Sealed) -> Result<String, Failure> {
    let (status, text) = post(&format!("{origin}/api/s"), &sealed.to_json())?;
    match status {
        201 => link::parse_created(&text)
            .map_err(|_| Failure::new(code::FAILED, "the server sent an unexpected reply")),
        429 => Err(Failure::new(
            code::FAILED,
            "too many requests: wait a minute and try again",
        )),
        507 => Err(Failure::new(
            code::FAILED,
            "the server is full: try again later",
        )),
        _ => Err(Failure::new(
            code::FAILED,
            format!("the server refused the request ({status})"),
        )),
    }
}

pub fn open(parsed: &link::ParsedLink) -> Result<link::Record, Failure> {
    let token =
        link::token_of(&parsed.secret).map_err(|e| Failure::new(code::FAILED, e.to_string()))?;
    let body = format!(r#"{{"token":"{}"}}"#, link::b64u_encode(token.as_slice()));
    let url = format!("{}/api/s/{}/open", parsed.origin, parsed.id);
    let (status, text) = post(&url, &body)?;
    match status {
        200 => link::parse_record(&text)
            .map_err(|_| Failure::new(code::FAILED, "the server sent an unexpected reply")),
        404 => Err(Failure::new(
            code::GONE,
            "this link cannot be used: it was already opened or has expired. If you did not open it, someone else may have. Ask the sender to revoke that key",
        )),
        429 => Err(Failure::new(
            code::FAILED,
            "too many requests: wait a minute and try again",
        )),
        _ => Err(Failure::new(
            code::FAILED,
            format!("the server refused the request ({status})"),
        )),
    }
}
