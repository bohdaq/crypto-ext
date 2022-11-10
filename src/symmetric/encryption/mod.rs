use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use crate::{generate_passphrase, get_path_relative_to_working_directory, get_static_filepath, read_file, read_or_create_and_write};

#[cfg(test)]
mod tests;

/// EncryptionParameters is basically the key and nonce
pub struct EncryptionParameters {
    pub key: String,
    pub nonce: String,
}

/// DecryptionParameters is basically the key and nonce
pub struct DecryptionParameters {
    pub key: String,
    pub nonce: String,
}

/// Will read or create EncryptionParameters and DecryptionParameters at the given location which is relative to the working directory
pub fn setup(path_to_encryption_parameters: Option<&str>) -> Result<(EncryptionParameters, DecryptionParameters), String> {
    let passphrase_64_bytes = generate_passphrase().unwrap();
    // key is 16 bytes long
    let aes_key = passphrase_64_bytes[48..64].to_string();
    // nonce is 12 bytes long
    let aes_nonce = passphrase_64_bytes[36..48].to_string();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".aes_key");
    let boxed_aes_key_path = get_static_filepath(relative_path.as_str());
    if boxed_aes_key_path.is_err() {
        return Err(boxed_aes_key_path.err().unwrap());
    }
    let aes_key_path = boxed_aes_key_path.unwrap();

    let boxed_aes_key = read_or_create_and_write(aes_key_path.as_str(), aes_key.as_bytes());
    if boxed_aes_key.is_err() {
        let message = boxed_aes_key.err().unwrap();
        return Err(message)
    }

    let boxed_aes_key = String::from_utf8(boxed_aes_key.unwrap());
    let aes_key = boxed_aes_key.unwrap();




    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".aes_nonce");
    let boxed_aes_nonce_path = get_static_filepath(relative_path.as_str());
    if boxed_aes_nonce_path.is_err() {
        return Err(boxed_aes_nonce_path.err().unwrap());
    }
    let aes_nonce_path = boxed_aes_nonce_path.unwrap();

    let boxed_aes_nonce = read_or_create_and_write(aes_nonce_path.as_str(), aes_nonce.as_bytes());
    if boxed_aes_nonce.is_err() {
        let message = boxed_aes_nonce.err().unwrap();
        return Err(message)
    }

    let boxed_aes_nonce = String::from_utf8(boxed_aes_nonce.unwrap());
    let aes_nonce = boxed_aes_nonce.unwrap();

    let encryption_params = EncryptionParameters { key: aes_key.to_string(), nonce: aes_nonce.to_string() };
    let decryption_params = DecryptionParameters { key: aes_key.to_string(), nonce: aes_nonce.to_string() };

    Ok((encryption_params, decryption_params))
}

/// Returns EncryptionParameters stored at the given location which is relative to the working directory
pub fn get_encryption_params(path_to_encryption_parameters: Option<&str>) -> Result<EncryptionParameters, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".aes_key");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }
    let public_key_path = boxed_public_key_path.unwrap();


    let boxed_public_key = read_file(public_key_path.as_str());
    if boxed_public_key.is_err() {
        let message = boxed_public_key.err().unwrap();
        return Err(message)
    }
    let boxed_public_key = String::from_utf8(boxed_public_key.unwrap());
    let aes_key = boxed_public_key.unwrap();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".aes_nonce");
    let boxed_aes_nonce_path = get_static_filepath(relative_path.as_str());
    if boxed_aes_nonce_path.is_err() {
        return Err(boxed_aes_nonce_path.err().unwrap());
    }
    let aes_nonce_path = boxed_aes_nonce_path.unwrap();


    let boxed_aes_nonce = read_file(aes_nonce_path.as_str());
    if boxed_aes_nonce.is_err() {
        let message = boxed_aes_nonce.err().unwrap();
        return Err(message)
    }
    let boxed_aes_nonce = String::from_utf8(boxed_aes_nonce.unwrap());
    let aes_nonce = boxed_aes_nonce.unwrap();

    let encryption_params = EncryptionParameters {
        key: aes_key.to_string(),
        nonce: aes_nonce.to_string(),
    };

    Ok(encryption_params)
}

/// Returns DecryptionParameters stored at the given location which is relative to the working directory
pub fn get_decryption_params(path_to_encryption_parameters: Option<&str>) -> Result<DecryptionParameters, String> {
    // in symmetric encryption same key and nonce used for encryption and decryption
    let boxed_encryption_params = get_encryption_params(path_to_encryption_parameters);
    if boxed_encryption_params.is_err() {
        let message = boxed_encryption_params.err().unwrap().to_string();
        return Err(message)
    }
    let encryption_params = boxed_encryption_params.unwrap();
    let decryption_params = DecryptionParameters {
        key: encryption_params.key.to_string(),
        nonce: encryption_params.nonce.to_string()
    };
    Ok(decryption_params)
}

/// Encrypts given byte array
///
/// # Examples
///
/// ```
///     use crypto_ext::symmetric::encryption::{decrypt, encrypt, get_decryption_params, get_encryption_params, setup};
///
///     #[test]
///     fn encryption() {
///         let data = "some data to encrypt".as_bytes();
///         let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker".as_bytes();
///
///         // path needs to be accessible by user with write permission for initial setup
///         // ideally for each encryption you need to setup unique folder for AES key and nonce
///         // do not reuse same setup with Encryption and Decryption parameters for multiple encryptions
///         let params_path = "/test/encryption_parameters/";
///
///
///         let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();
///
///         let encrypted = encrypt(encryption_params, data, associated_data).unwrap();
///
///         let decrypted = decrypt(decryption_params, encrypted.as_slice(), associated_data).unwrap();
///
///         assert_eq!(data, decrypted);
///
///     }
///
/// ```
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

pub fn decrypt(params: DecryptionParameters, encrypted_data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, String> {
    let payload = Payload {
        msg: encrypted_data,
        aad: associated_data,
    };

    let key = GenericArray::from_slice(params.key.as_bytes());
    let nonce = GenericArray::from_slice(params.nonce.as_bytes());

    let cipher = Aes128Gcm::new(key);
    let boxed_decrypted_data = cipher.decrypt(nonce, payload);
    if boxed_decrypted_data.is_err() {
        let message = boxed_decrypted_data.err().unwrap().to_string();
        return Err(message)
    }

    let decrypted_data = boxed_decrypted_data.unwrap();

    Ok(decrypted_data)
}
