use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

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

pub fn encrypt(params: EncryptionParameters, data_to_encrypt: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, String> {
    let payload = Payload {
        msg: data_to_encrypt,
        aad: associated_data,
    };

    let key = GenericArray::from_slice(params.key.as_bytes());
    let nonce = GenericArray::from_slice(params.nonce.as_bytes());

    let cipher = Aes128Gcm::new(key);
    let boxed_cipher_text = cipher.encrypt(nonce, payload);
    if boxed_cipher_text.is_err() {
        let message = boxed_cipher_text.err().unwrap().to_string();
        return Err(message)
    }

    let cipher_text = boxed_cipher_text.unwrap();

    Ok(cipher_text)
}
