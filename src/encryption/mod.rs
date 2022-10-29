use std::{env};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use sha256::digest;
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

#[cfg(test)]
mod tests;

pub const RSA_SIZE: u32 = 4096;

pub struct EncryptionParameters {
    pub passphrase: String,
    pub private_key: String,
    pub public_key: String,
    pub padding: String,
    pub cipher: String,
}

pub fn setup_encryption(path_to_encryption_parameters: Option<&str>) -> Result<EncryptionParameters, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".passphrase");
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


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".public_key");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }
    let public_key_path = boxed_public_key_path.unwrap();


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".private_key");
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

    let padding = "PKCS1".to_string();
    let cipher = "aes_128_cbc".to_string();

    let params = EncryptionParameters {
        passphrase,
        private_key,
        public_key,
        padding,
        cipher,
    };

    Ok(params)
}

pub fn encrypt(public_key: &str, data: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(public_key.as_bytes()).unwrap();
    let mut buffer : Vec<u8> = vec![0; rsa.size() as usize];
    let _ = rsa.public_encrypt(data, &mut buffer, Padding::PKCS1).unwrap();
    buffer
}

pub fn decrypt(private_key: &str, passphrase: &str, data: &[u8]) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem_passphrase(private_key.as_bytes(), passphrase.as_bytes()).unwrap();
    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];
    let _ = rsa.private_decrypt(data, &mut buffer, Padding::PKCS1).unwrap();
    buffer
}

pub fn get_or_create_passphrase(path: &str) -> Result<String, String> {

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

pub fn read_or_create_and_write(path: &str, content: &str) -> Result<String, String> {
    let does_passphrase_exist = does_file_exist(path);
    return if does_passphrase_exist {
        let boxed_read = read_file(path);
        if boxed_read.is_err() {
            return Err(boxed_read.err().unwrap());
        }
        let passphrase = boxed_read.unwrap();
        Ok(passphrase)
    } else {
        let boxed_create = create_file(path);
        if boxed_create.is_err() {
            let message = boxed_create.err().unwrap();
            return Err(message)
        }

        let boxed_write = write_file(path, content.as_bytes());
        if boxed_write.is_err() {
            let message = boxed_write.err().unwrap();
            return Err(message)
        }
        Ok(content.to_string())
    }
}

pub fn create_file(path: &str) -> Result<File, String>  {
    let boxed_file = File::create(path);

    if boxed_file.is_err() {
        let message = format!("unable to create file: {}", boxed_file.err().unwrap());
        return Err(message)
    }

    let file = boxed_file.unwrap();
    Ok(file)
}

pub fn does_file_exist(path: &str) -> bool {
    let file_exists = Path::new(path).is_file();
    file_exists
}

pub fn read_file(path: &str) -> Result<String, String> {
    let mut file_contents : String = "".to_string();
    let boxed_open = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path);
    if boxed_open.is_err() {
        let message = format!("unable to read from file: {}", boxed_open.err().unwrap());
        return Err(message)
    }

    let mut file = boxed_open.unwrap();

    let boxed_read = file.read_to_string(&mut file_contents);
    if boxed_read.is_err() {
        let message = format!("unable to read from file: {}", boxed_read.err().unwrap());
        return Err(message)
    }

    Ok(file_contents)
}

pub fn write_file(path: &str, file_content: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(false)
        .write(true)
        .create(false)
        .truncate(false)
        .open(path)
        .unwrap();
    let boxed_write = file.write_all(file_content);
    if boxed_write.is_err() {
        let message = format!("unable to write to file: {}", boxed_write.err().unwrap());
        return Err(message)
    }
    Ok(())
}

pub fn overwrite_file(path: &str, file_content: &[u8]) -> Result<(), String>{
    let mut file = OpenOptions::new()
        .read(false)
        .write(true)
        .create(false)
        .truncate(true)
        .open(path)
        .unwrap();
    let boxed_write = file.write_all(file_content);
    if boxed_write.is_err() {
        let message = format!("unable to overwrite to file: {}", boxed_write.err().unwrap());
        return Err(message)
    }
    Ok(())
}

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

pub fn get_or_create_private_public_keys(passphrase: &str, public_key_path: &str, private_key_path: &str) -> Result<(String, String), String> {
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

pub fn get_static_filepath(path: &str) -> Result<String, String> {
    let boxed_dir = env::current_dir();
    if boxed_dir.is_err() {
        let error = boxed_dir.err().unwrap();
        eprintln!("{}", error);
        return Err(error.to_string());
    }
    let dir = boxed_dir.unwrap();


    let boxed_working_directory = dir.as_path().to_str();
    if boxed_working_directory.is_none() {
        let error = "working directory is not set";
        eprintln!("{}", error);
        return Err(error.to_string());
    }

    let working_directory = boxed_working_directory.unwrap();
    let absolute_path = [working_directory, path].join("");
    Ok(absolute_path)
}

pub fn get_path_relative_to_working_directory(boxed_path_to_encryption_parameters: Option<&str>, filename: &str) -> String {
    if boxed_path_to_encryption_parameters.is_some() {
        let path_to_encryption_parameters = boxed_path_to_encryption_parameters.unwrap();
        return [path_to_encryption_parameters, filename].join("");
    }

    filename.to_string()
}