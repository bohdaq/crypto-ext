use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use crate::{generate_passphrase, get_path_relative_to_working_directory, get_static_filepath, read_file, read_or_create_and_write};

#[cfg(test)]
mod tests;

const RSA_SIZE: u32 = 4096;

/// EncryptionParameters is basically a public key
///
pub struct EncryptionParameters {
    pub rsa_public_key_pem: String,
}

/// DecryptionParameters is basically a private key and passphrase
///
pub struct DecryptionParameters {
    pub rsa_passphrase: String,
    pub rsa_private_key_pem: String,
}

/// Will read or create EncryptionParameters and DecryptionParameters at the given location which is relative to the working directory
///
pub fn setup(path_to_encryption_parameters: Option<&str>) -> Result<(EncryptionParameters, DecryptionParameters), String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_passphrase");
    let boxed_passphrase_path = get_static_filepath(relative_path.as_str());
    if boxed_passphrase_path.is_err() {
        return Err(boxed_passphrase_path.err().unwrap());
    }
    let passphrase_path = boxed_passphrase_path.unwrap();


    let boxed_passphrase = get_or_create_passphrase(passphrase_path.as_str());
    if boxed_passphrase.is_err() {
        return Err(boxed_passphrase.err().unwrap());
    }
    let passphrase = boxed_passphrase.unwrap();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_public_key");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }
    let public_key_path = boxed_public_key_path.unwrap();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_private_key");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }
    let private_key_path = boxed_private_key_path.unwrap();


    let boxed_keys = get_or_create_private_public_keys(passphrase.as_str(), public_key_path.as_str(), private_key_path.as_str());
    if boxed_keys.is_err() {
        return Err(boxed_keys.err().unwrap());
    }

    let (private_key, public_key) = boxed_keys.unwrap();

    let encryption_params = EncryptionParameters {
        rsa_public_key_pem: public_key,
    };

    let decryption_params = DecryptionParameters {
        rsa_passphrase: passphrase,
        rsa_private_key_pem: private_key
    };

    Ok((encryption_params, decryption_params))
}

/// Returns EncryptionParameters stored at the given location which is relative to the working directory
///
pub fn get_encryption_params(path_to_encryption_parameters: Option<&str>) -> Result<EncryptionParameters, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_public_key");
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
    let public_key = boxed_public_key.unwrap();

    let encryption_params = EncryptionParameters {
        rsa_public_key_pem: public_key,
    };

    Ok(encryption_params)
}

/// Returns DecryptionParameters stored at the given location which is relative to the working directory
///
pub fn get_decryption_params(path_to_encryption_parameters: Option<&str>) -> Result<DecryptionParameters, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_passphrase");
    let boxed_passphrase_path = get_static_filepath(relative_path.as_str());
    if boxed_passphrase_path.is_err() {
        return Err(boxed_passphrase_path.err().unwrap());
    }
    let passphrase_path = boxed_passphrase_path.unwrap();


    let boxed_passphrase = get_or_create_passphrase(passphrase_path.as_str());
    if boxed_passphrase.is_err() {
        return Err(boxed_passphrase.err().unwrap());
    }
    let passphrase = boxed_passphrase.unwrap();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".rsa_private_key");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }
    let private_key_path = boxed_private_key_path.unwrap();

    let boxed_private_key = read_file(private_key_path.as_str());
    if boxed_private_key.is_err() {
        let message = boxed_private_key.err().unwrap();
        return Err(message)
    }
    let boxed_private_key = String::from_utf8(boxed_private_key.unwrap());
    let private_key = boxed_private_key.unwrap();

    let decryption_params = DecryptionParameters {
        rsa_passphrase: passphrase,
        rsa_private_key_pem: private_key
    };

    Ok(decryption_params)
}

/// Encrypts given byte array of maximum length up to 501 bytes
///
/// # Examples
///
/// ```
///    use crypto_ext::asymmetric::encryption::{encrypt, decrypt, EncryptionParameters, DecryptionParameters, setup, get_encryption_params, get_decryption_params};
///
///    #[test]
///    fn encryption() {
///        //maximum 501 bytes at once to be encrypted
///        let data_to_encrypt_as_bytes = "Some data to encrypt".as_bytes();
///
///        // path needs to be accessible by user with write permission for initial setup
///        let params_path = "/test/encryption_parameters/";
///        // it will read encryption params like public, private keys and passphrase or create them
///        // in this example setup is used to populate the params and used later via get_encryption_params or get_decryption_params
///        let _ = setup(Some(params_path));
///
///        let encryption_params  = get_encryption_params(Some(params_path)).unwrap();
///        let encrypted_bytes = encrypt(encryption_params, data_to_encrypt_as_bytes).unwrap();
///
///        let decryption_params = get_decryption_params(Some(params_path)).unwrap();
///        let decrypted_bytes = decrypt(decryption_params, encrypted_bytes.as_slice()).unwrap();
///
///        assert_eq!(data_to_encrypt_as_bytes, decrypted_bytes);
///    }
/// ```
pub fn encrypt(params: EncryptionParameters, data: &[u8]) -> Result<Vec<u8>, String> {
    let boxed_rsa = Rsa::public_key_from_pem(params.rsa_public_key_pem.as_bytes());
    if boxed_rsa.is_err() {
        let message = boxed_rsa.err().unwrap().to_string();
        return Err(message)
    }
    let rsa = boxed_rsa.unwrap();
    let mut buffer : Vec<u8> = vec![0; rsa.size() as usize];
    let boxed_encrypt = rsa.public_encrypt(data, &mut buffer, Padding::PKCS1);
    if boxed_encrypt.is_err() {
        let message = boxed_encrypt.err().unwrap().to_string();
        return Err(message)
    }
    let _ = boxed_encrypt.unwrap();
    Ok(buffer)
}


/// Decrypts given byte array
///
/// # Examples
///
/// ```
///    use crypto_ext::asymmetric::encryption::{encrypt, decrypt, EncryptionParameters, DecryptionParameters, setup, get_encryption_params, get_decryption_params};
///
///    #[test]
///    fn decryption() {
///        // to decrypt first we need to have encrypted data
///        let data_to_encrypt_as_bytes = "Some data to encrypt".as_bytes();
///
///        // path needs to be accessible by user with write permission for initial setup
///        let params_path = "/test/encryption_parameters/";
///        // this will create encryption params like public, private keys and passphrase
///        let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();
///
///        let encrypted_bytes = encrypt(encryption_params, data_to_encrypt_as_bytes).unwrap();
///        let decrypted_bytes = decrypt(decryption_params, encrypted_bytes.as_slice()).unwrap();
///
///        assert_eq!(data_to_encrypt_as_bytes, decrypted_bytes);
///    }
/// ```
pub fn decrypt(params: DecryptionParameters, data: &[u8]) -> Result<Vec<u8>, String> {
    let boxed_rsa = Rsa::private_key_from_pem_passphrase(params.rsa_private_key_pem.as_bytes(), params.rsa_passphrase.as_bytes());
    if boxed_rsa.is_err() {
        let message = boxed_rsa.err().unwrap().to_string();
        return Err(message)
    }
    let rsa = boxed_rsa.unwrap();
    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];
    let boxed_decrypt = rsa.private_decrypt(data, &mut buffer, Padding::PKCS1);
    if boxed_decrypt.is_err() {
        let message = boxed_decrypt.err().unwrap().to_string();
        return Err(message)
    }
    let _ = boxed_decrypt.unwrap();

    let as_string = String::from_utf8(buffer).expect("Found invalid UTF-8");

    let as_filtered_string = as_string.trim_end_matches(char::from(0));

    let as_vector = as_filtered_string.as_bytes().to_vec();

    Ok(as_vector)
}


// below are functions not exposed as an api, used for inner implementation

fn get_or_create_passphrase(path: &str) -> Result<String, String> {

    let boxed_passphrase = generate_passphrase();
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();

    let boxed_passphrase = read_or_create_and_write(path, passphrase.as_bytes());
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let boxed_passphrase = String::from_utf8(boxed_passphrase.unwrap());
    let passphrase = boxed_passphrase.unwrap();
    Ok(passphrase)
}

fn get_or_create_private_public_keys(passphrase: &str, public_key_path: &str, private_key_path: &str) -> Result<(String, String), String> {
    let rsa = Rsa::generate(RSA_SIZE).unwrap();

    let boxed_private_key = rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes());
    let boxed_private_key = String::from_utf8(boxed_private_key.unwrap());
    let private_key  = boxed_private_key.unwrap();

    let boxed_private_key = read_or_create_and_write(private_key_path, private_key.as_bytes());
    if boxed_private_key.is_err() {
        let message = boxed_private_key.err().unwrap();
        return Err(message)
    }
    let boxed_private_key = String::from_utf8(boxed_private_key.unwrap());
    let private_key = boxed_private_key.unwrap();


    let boxed_public_key = rsa.public_key_to_pem();
    let boxed_public_key = String::from_utf8(boxed_public_key.unwrap());
    let public_key = boxed_public_key.unwrap();

    let boxed_public_key = read_or_create_and_write(public_key_path, public_key.as_bytes());
    if boxed_public_key.is_err() {
        let message = boxed_public_key.err().unwrap();
        return Err(message)
    }
    let boxed_public_key = String::from_utf8(boxed_public_key.unwrap());
    let public_key = boxed_public_key.unwrap();

    Ok((private_key.to_string(), public_key.to_string()))
}

