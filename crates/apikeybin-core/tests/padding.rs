//! Padding on its own: a size outside the classes, and content that does not fit its class.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use apikeybin_core::Error;
use apikeybin_core::padding::{self, BUCKETS};

#[test]
fn only_the_known_sizes_can_be_padded_to() {
    for size in [0u32, 1, 100, 1023, 1025, 2048, 1_048_577] {
        assert_eq!(
            padding::pad(b"x", size).err(),
            Some(Error::BadBucket),
            "{size}"
        );
    }
}

#[test]
fn only_the_known_sizes_can_be_read_from() {
    // Well formed apart from its size: a correct length prefix, the content, then zeros.
    for size in [5u32, 100, 1023, 2048] {
        let mut padded = vec![0u8; usize::try_from(size).unwrap()];
        padded[3] = 1;
        padded[4] = b'x';
        assert_eq!(
            padding::unpad(&padded, size).err(),
            Some(Error::BadBucket),
            "{size}"
        );
    }
}

#[test]
fn content_that_does_not_fit_its_size_is_refused_rather_than_cut() {
    for bucket in BUCKETS {
        let size = usize::try_from(bucket).unwrap();
        let fits = vec![0x41u8; size - 4];
        let padded = padding::pad(&fits, bucket).unwrap();
        assert_eq!(padded.len(), size);
        assert_eq!(padding::unpad(&padded, bucket).unwrap(), &fits[..]);

        let over = vec![0x41u8; size - 3];
        assert_eq!(
            padding::pad(&over, bucket).err(),
            Some(Error::PayloadTooLarge),
            "{bucket}"
        );
    }
}
