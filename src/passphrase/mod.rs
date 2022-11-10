use std::time::{SystemTime, UNIX_EPOCH};
use sha256::digest;

#[cfg(test)]
mod tests;

/// Generates 256-bit long passphrase
///
/// # Examples
///
/// ```
///
///     use crypto_ext::passphrase::generate_passphrase;
///
///     #[test]
///     fn passphrase() {
///         let passphrase = generate_passphrase().unwrap();
///         assert_eq!(passphrase.len(), 64);
///     }
///
/// ```
pub fn generate_passphrase() -> Result<String, String> {
    let now = SystemTime::now();
    let boxed_time_in_nanos = now.duration_since(UNIX_EPOCH);
    if boxed_time_in_nanos.is_err() {
        let message = format!("unable to get system time: {}", boxed_time_in_nanos.err().unwrap());
        return Err(message)
    }
    let time_in_nanos = boxed_time_in_nanos.unwrap().as_nanos();
    let hex_time_in_millis = format!("{time_in_nanos:X}");
    let sha_timestamp = digest(hex_time_in_millis);
    Ok(sha_timestamp)
}