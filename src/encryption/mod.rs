use std::time::{SystemTime, UNIX_EPOCH};
use sha256::digest;
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use crate::{get_path_relative_to_working_directory, get_static_filepath, read_file, read_or_create_and_write};

#[cfg(test)]
mod tests;

const RSA_SIZE: u32 = 4096;

pub struct EncryptionParameters {
    pub rsa_public_key_pem: String,
}

pub struct DecryptionParameters {
    pub rsa_passphrase: String,
    pub rsa_private_key_pem: String,
}

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
    let public_key = boxed_public_key.unwrap();

    let encryption_params = EncryptionParameters {
        rsa_public_key_pem: public_key,
    };

    Ok(encryption_params)
}

pub fn setup_decryption(path_to_encryption_parameters: Option<&str>) -> Result<DecryptionParameters, String> {
    let boxed_params = setup(path_to_encryption_parameters);
    if boxed_params.is_err() {
        return Err(boxed_params.err().unwrap());
    }

    let (_, params) = boxed_params.unwrap();
    Ok(params)
}


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
    Ok(buffer)
}

fn get_or_create_passphrase(path: &str) -> Result<String, String> {

    let boxed_passphrase = generate_passphrase();
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();

    let boxed_passphrase = read_or_create_and_write(path, passphrase.as_str());
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();
    Ok(passphrase)
}

fn generate_passphrase() -> Result<String, String> {
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

fn get_or_create_private_public_keys(passphrase: &str, public_key_path: &str, private_key_path: &str) -> Result<(String, String), String> {
    let rsa = Rsa::generate(RSA_SIZE).unwrap();

    let boxed_private_key = rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes());
    let private_key  = String::from_utf8(boxed_private_key.unwrap()).unwrap();

    let boxed_private_key = read_or_create_and_write(private_key_path, private_key.as_str());
    if boxed_private_key.is_err() {
        let message = boxed_private_key.err().unwrap();
        return Err(message)
    }
    let private_key = boxed_private_key.unwrap();


    let boxed_public_key = rsa.public_key_to_pem();
    let public_key = String::from_utf8(boxed_public_key.unwrap()).unwrap();

    let boxed_public_key = read_or_create_and_write(public_key_path, public_key.as_str());
    if boxed_public_key.is_err() {
        let message = boxed_public_key.err().unwrap();
        return Err(message)
    }
    let public_key = boxed_public_key.unwrap();

    Ok((private_key.to_string(), public_key.to_string()))
}

