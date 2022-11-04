#[cfg(test)]
mod tests;

pub struct EncryptionParameters {
    pub key: String,
    pub nonce: String,
}

pub struct DecryptionParameters {
    pub key: String,
    pub nonce: String,
}
