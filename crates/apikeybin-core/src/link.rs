//! The link format shared with the browser version (`web/public/app.js`). See docs/SPEC.md §19.
//!
//! `https://app.apikeybin.com/s/<id>#1.<secret>` or `#1p.<secret>` when a passphrase is also needed.
//! The AEAD here is AES-256-GCM because that is what browsers have. Each key encrypts one message.

use core::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::text;

pub const BUCKETS: [usize; 4] = [1024, 4096, 16384, 65536];
pub const MAX_TEXT: usize = 65536 - LEN_PREFIX - NAME_PREFIX;
pub const MAX_NAME: usize = 128;
pub const TTLS: [u32; 4] = [600, 3600, 86400, 604800];
const LEN_PREFIX: usize = 4;
const NAME_PREFIX: usize = 2;
const AAD: &[u8] = b"apikeybin/link/1";
const PBKDF2_ITERATIONS: u32 = 600_000;
const ID_LEN: usize = 22;
const SECRET_LEN: usize = 32;

const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64u_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(char::from(sym((acc >> bits) & 0x3f)));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(sym((acc << (6 - bits)) & 0x3f)));
    }
    out
}

fn sym(index: u32) -> u8 {
    B64U.get(index as usize).copied().unwrap_or(b'A')
}

/// Strict: only the URL-safe alphabet, no padding, and the unused trailing bits must be zero, so
/// each byte string has exactly one spelling.
pub fn b64u_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for ch in text.bytes() {
        let value = B64U.iter().position(|c| *c == ch).ok_or(Error::Decode)?;
        acc = (acc << 6) | u32::try_from(value).map_err(|_| Error::Decode)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).map_err(|_| Error::Decode)?);
        }
        acc &= (1 << bits) - 1;
    }
    if bits >= 6 || acc != 0 {
        return Err(Error::Decode);
    }
    Ok(out)
}

fn hkdf(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// What the server is shown to prove the link is held. It keeps only the SHA-256 of this.
pub fn token_of(secret: &[u8; SECRET_LEN]) -> Result<Zeroizing<[u8; 32]>, Error> {
    hkdf(secret, b"apikeybin/link/1/token")
}

fn key_of(
    secret: &[u8; SECRET_LEN],
    passphrase: Option<&str>,
    salt: Option<&[u8; 16]>,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    match (passphrase, salt) {
        (None, None) => hkdf(secret, b"apikeybin/link/1/key"),
        (Some(pass), Some(salt)) => {
            let mut stretched = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(
                pass.as_bytes(),
                salt,
                PBKDF2_ITERATIONS,
                stretched.as_mut_slice(),
            );
            let mut ikm = Zeroizing::new([0u8; 64]);
            ikm.get_mut(..32)
                .ok_or(Error::Crypto)?
                .copy_from_slice(secret);
            ikm.get_mut(32..)
                .ok_or(Error::Crypto)?
                .copy_from_slice(stretched.as_slice());
            hkdf(ikm.as_slice(), b"apikeybin/link/1/key+pw")
        }
        _ => Err(Error::Crypto),
    }
}

/// A file name comes from someone else and ends up on screen and on disk.
///
/// Spaces at either end and a dot at the end are refused because some systems drop them on saving,
/// which would turn `a.html.` into `a.html` after anything that looked at the name.
pub fn valid_name(name: &str) -> bool {
    text::validate(name, MAX_NAME).is_ok()
        && !name.contains(['/', '\\', ':'])
        && !name.starts_with(char::is_whitespace)
        && !name.ends_with(|c: char| c.is_whitespace() || c == '.')
}

/// The file name, if there is one, then the content. The name is encrypted with the rest.
fn frame(name: Option<&str>, content: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let name = name.unwrap_or("");
    if !name.is_empty() && !valid_name(name) {
        return Err(Error::BadText);
    }
    let length = u16::try_from(name.len()).map_err(|_| Error::BadText)?;
    let mut out = Zeroizing::new(Vec::with_capacity(NAME_PREFIX + name.len() + content.len()));
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(content);
    Ok(out)
}

fn unframe(body: &[u8]) -> Result<(Option<String>, &[u8]), Error> {
    let (prefix, rest) = body
        .split_at_checked(NAME_PREFIX)
        .ok_or(Error::BadPadding)?;
    let prefix: [u8; 2] = prefix.try_into().map_err(|_| Error::BadPadding)?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length > MAX_NAME {
        return Err(Error::BadText);
    }
    let (name, content) = rest.split_at_checked(length).ok_or(Error::BadPadding)?;
    if length == 0 {
        return Ok((None, content));
    }
    let name = core::str::from_utf8(name).map_err(|_| Error::BadText)?;
    if !valid_name(name) {
        return Err(Error::BadText);
    }
    Ok((Some(name.to_owned()), content))
}

fn pad(text: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let needed = text
        .len()
        .checked_add(LEN_PREFIX)
        .ok_or(Error::PayloadTooLarge)?;
    let bucket = BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= needed)
        .ok_or(Error::PayloadTooLarge)?;
    let declared = u32::try_from(text.len()).map_err(|_| Error::PayloadTooLarge)?;
    let mut out = Zeroizing::new(Vec::with_capacity(bucket));
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(text);
    out.resize(bucket, 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    if !BUCKETS.contains(&padded.len()) {
        return Err(Error::BadPadding);
    }
    let (prefix, rest) = padded
        .split_at_checked(LEN_PREFIX)
        .ok_or(Error::BadPadding)?;
    let prefix: [u8; 4] = prefix.try_into().map_err(|_| Error::BadPadding)?;
    let declared = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::BadPadding)?;
    let (body, zeros) = rest.split_at_checked(declared).ok_or(Error::BadPadding)?;
    if zeros.iter().any(|b| *b != 0) {
        return Err(Error::BadPadding);
    }
    Ok(body)
}

/// The `POST /api/s` body, already validated, with its values base64url encoded.
#[derive(Debug)]
pub struct Sealed {
    pub iv: String,
    pub ct: String,
    pub token_hash: String,
    pub ttl: u32,
    pub salt: Option<String>,
}

impl Sealed {
    /// Every value is base64url or a number, so nothing here needs escaping.
    pub fn to_json(&self) -> String {
        let mut out = format!(
            r#"{{"v":1,"iv":"{}","ct":"{}","token_hash":"{}","ttl":{},"pw":{}"#,
            self.iv,
            self.ct,
            self.token_hash,
            self.ttl,
            self.salt.is_some()
        );
        if let Some(salt) = &self.salt {
            out.push_str(&format!(r#","salt":"{salt}""#));
        }
        out.push('}');
        out
    }
}

/// Encrypts text for a new link. Takes the randomness as arguments so that tests can check it
/// against known answers; `seal` fills it from the OS.
pub fn seal_with(
    text: &[u8],
    name: Option<&str>,
    passphrase: Option<&str>,
    ttl: u32,
    secret: &[u8; SECRET_LEN],
    iv: &[u8; 12],
    salt: Option<&[u8; 16]>,
) -> Result<Sealed, Error> {
    if !TTLS.contains(&ttl) {
        return Err(Error::Decode);
    }
    let padded = pad(&frame(name, text)?)?;
    let key = key_of(secret, passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let ct = cipher
        .encrypt(
            &Nonce::from(*iv),
            Payload {
                msg: &padded,
                aad: AAD,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let hash = Sha256::digest(token_of(secret)?.as_slice());
    Ok(Sealed {
        iv: b64u_encode(iv),
        ct: b64u_encode(&ct),
        token_hash: b64u_encode(hash.as_slice()),
        ttl,
        salt: salt.map(|s| b64u_encode(s)),
    })
}

/// Encrypts text for a new link. Returns the request and the secret that goes after the `#`.
pub fn seal(
    text: &[u8],
    name: Option<&str>,
    passphrase: Option<&str>,
    ttl: u32,
) -> Result<(Sealed, Zeroizing<[u8; SECRET_LEN]>), Error> {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    getrandom::fill(secret.as_mut_slice()).map_err(|_| Error::Rng)?;
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(|_| Error::Rng)?;
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|_| Error::Rng)?;
    let salt = passphrase.map(|_| &salt_bytes);
    let sealed = seal_with(text, name, passphrase, ttl, &secret, &iv, salt)?;
    Ok((sealed, secret))
}

/// Random text for a temporary file name.
pub fn random_hex() -> Result<String, Error> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| Error::Rng)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn fragment(secret: &[u8; SECRET_LEN], needs_passphrase: bool) -> String {
    format!(
        "{}.{}",
        if needs_passphrase { "1p" } else { "1" },
        b64u_encode(secret)
    )
}

/// A link taken apart. Debug never shows the secret.
pub struct ParsedLink {
    pub origin: String,
    pub id: String,
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
    pub needs_passphrase: bool,
}

impl fmt::Debug for ParsedLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedLink")
            .field("origin", &self.origin)
            .field("id", &self.id)
            .field("secret", &"[redacted]")
            .field("needs_passphrase", &self.needs_passphrase)
            .finish()
    }
}

/// True for what may carry the token: HTTPS anywhere, plain HTTP only on this machine.
pub fn allowed_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    if authority.is_empty()
        || !authority
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b':')
    {
        return false;
    }
    match scheme {
        "https" => true,
        "http" => {
            let host = authority.split(':').next().unwrap_or("");
            host == "localhost" || host == "127.0.0.1"
        }
        _ => false,
    }
}

/// Accepts exactly `<origin>/s/<22 characters>#<1 or 1p>.<43 characters>`.
pub fn parse(link: &str) -> Result<ParsedLink, Error> {
    let (head, frag) = link.trim().split_once('#').ok_or(Error::Decode)?;
    let (origin, id) = head.rsplit_once("/s/").ok_or(Error::Decode)?;
    if !allowed_origin(origin) {
        return Err(Error::Decode);
    }
    if id.len() != ID_LEN || b64u_decode(id).map(|b| b.len()) != Ok(16) {
        return Err(Error::Decode);
    }
    let (version, secret_text) = frag.split_once('.').ok_or(Error::Decode)?;
    let needs_passphrase = match version {
        "1" => false,
        "1p" => true,
        _ => return Err(Error::Decode),
    };
    let decoded = Zeroizing::new(b64u_decode(secret_text)?);
    let secret: [u8; SECRET_LEN] = decoded.as_slice().try_into().map_err(|_| Error::Decode)?;
    Ok(ParsedLink {
        origin: origin.to_owned(),
        id: id.to_owned(),
        secret: Zeroizing::new(secret),
        needs_passphrase,
    })
}

/// The record the server returned when the link was opened.
#[derive(Debug)]
pub struct Record {
    pub iv: String,
    pub ct: String,
    pub pw: bool,
    pub salt: Option<String>,
}

/// What came out of a record. Debug never shows the content.
pub struct Opened {
    pub name: Option<String>,
    pub content: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opened")
            .field("name", &self.name)
            .field("content", &"[redacted]")
            .finish()
    }
}

/// Decrypts. A wrong passphrase and a damaged record look the same here, on purpose: AES-GCM
/// cannot tell them apart.
pub fn open(
    record: &Record,
    secret: &[u8; SECRET_LEN],
    passphrase: Option<&str>,
) -> Result<Opened, Error> {
    let iv: [u8; 12] = b64u_decode(&record.iv)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decode)?;
    let ct = b64u_decode(&record.ct)?;
    let salt = match (&record.salt, record.pw) {
        (Some(text), true) => {
            let bytes: [u8; 16] = b64u_decode(text)?
                .as_slice()
                .try_into()
                .map_err(|_| Error::Decode)?;
            Some(bytes)
        }
        (None, false) => None,
        _ => return Err(Error::Decode),
    };
    let key = key_of(secret, passphrase, salt.as_ref())?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let padded = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(iv), Payload { msg: &ct, aad: AAD })
            .map_err(|_| Error::Crypto)?,
    );
    let (name, content) = unframe(unpad(&padded)?)?;
    Ok(Opened {
        name,
        content: Zeroizing::new(content.to_vec()),
    })
}

/// A strict reader for this API's replies: one flat object of strings without escapes, integers,
/// and booleans. Anything else is refused rather than interpreted.
pub fn flat_json(text: &str) -> Result<Vec<(String, FlatValue)>, Error> {
    let body = text
        .trim()
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .ok_or(Error::Decode)?;
    let mut out: Vec<(String, FlatValue)> = Vec::new();
    if body.trim().is_empty() {
        return Ok(out);
    }
    for field in body.split(',') {
        let (key, value) = field.split_once(':').ok_or(Error::Decode)?;
        let key = plain_string(key.trim())?;
        if out.iter().any(|(k, _)| *k == key) {
            return Err(Error::Decode);
        }
        let value = value.trim();
        let parsed = if value == "true" {
            FlatValue::Bool(true)
        } else if value == "false" {
            FlatValue::Bool(false)
        } else if value.starts_with('"') {
            FlatValue::Text(plain_string(value)?)
        } else if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) {
            FlatValue::Number(value.parse().map_err(|_| Error::Decode)?)
        } else {
            return Err(Error::Decode);
        };
        out.push((key, parsed));
    }
    Ok(out)
}

fn plain_string(text: &str) -> Result<String, Error> {
    let inner = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or(Error::Decode)?;
    if inner
        .bytes()
        .any(|c| c == b'"' || c == b'\\' || c.is_ascii_control())
    {
        return Err(Error::Decode);
    }
    Ok(inner.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlatValue {
    Text(String),
    Number(u64),
    Bool(bool),
}

/// Reads the reply to opening a link. Unknown fields are refused.
pub fn parse_record(text: &str) -> Result<Record, Error> {
    let (mut v, mut iv, mut ct, mut pw, mut salt) = (false, None, None, None, None);
    for (key, value) in flat_json(text)? {
        match (key.as_str(), value) {
            ("v", FlatValue::Number(1)) => v = true,
            ("iv", FlatValue::Text(t)) => iv = Some(t),
            ("ct", FlatValue::Text(t)) => ct = Some(t),
            ("pw", FlatValue::Bool(b)) => pw = Some(b),
            ("salt", FlatValue::Text(t)) => salt = Some(t),
            _ => return Err(Error::Decode),
        }
    }
    match (v, iv, ct, pw) {
        (true, Some(iv), Some(ct), Some(pw)) => Ok(Record { iv, ct, pw, salt }),
        _ => Err(Error::Decode),
    }
}

/// Reads the reply to creating a link, and returns the id after checking its shape.
pub fn parse_created(text: &str) -> Result<String, Error> {
    let mut id = None;
    for (key, value) in flat_json(text)? {
        match (key.as_str(), value) {
            ("id", FlatValue::Text(t)) => id = Some(t),
            ("expires_at", FlatValue::Number(_)) => {}
            _ => return Err(Error::Decode),
        }
    }
    let id = id.ok_or(Error::Decode)?;
    if id.len() != ID_LEN || b64u_decode(&id).map(|b| b.len()) != Ok(16) {
        return Err(Error::Decode);
    }
    Ok(id)
}
