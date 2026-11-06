//! Text that came from another machine and will reach a terminal: labels and device
//! names. Rejecting is simpler to reason about than escaping, and a legitimate name
//! never needs any of these characters.

use crate::error::Error;

pub const MAX_LABEL_BYTES: usize = 128;
pub const MAX_DEVICE_NAME_BYTES: usize = 64;

/// Control characters, and every character that shows nothing: Default_Ignorable_Code_Point in
/// Unicode 18.0, which covers zero width, direction overrides, variation selectors and tags, plus
/// the line and paragraph separators and interlinear annotation.
pub fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF0..=0xFFF8
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
            | 0x2028..=0x2029
            | 0xFFF9..=0xFFFB
        )
}

pub fn validate(text: &str, max_bytes: usize) -> Result<(), Error> {
    if text.is_empty() || text.len() > max_bytes || text.chars().any(is_forbidden) {
        return Err(Error::BadText);
    }
    Ok(())
}
