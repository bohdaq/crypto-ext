
#[cfg(test)]
mod tests;

pub const DSA_SIZE: u32 = 4096;

pub fn setup_signature(path_to_encryption_parameters: Option<&str>) {

}

pub fn sign(private_key: &str, passphrase: &str, data: &[u8]) -> String {
    //TODO:
    "".to_string()
}

pub fn verify(public_key: &str, data: &[u8], signature: &str) -> bool {
    //TODO
    false
}
