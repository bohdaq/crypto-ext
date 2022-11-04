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

pub fn encrypt(params: EncryptionParameters, data_to_encrypt: &[u8], associated_data: &[u8]) -> Vec<u8> {
    //TODO:
    let encrypted_data = vec![];

    encrypted_data
}
