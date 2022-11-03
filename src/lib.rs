use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use sha256::digest;

pub mod asymmetric;
pub mod symmetric;

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


// below are functions not exposed as an api, used for inner implementation

fn get_static_filepath(path: &str) -> Result<String, String> {
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

fn get_path_relative_to_working_directory(boxed_path_to_encryption_parameters: Option<&str>, filename: &str) -> String {
    if boxed_path_to_encryption_parameters.is_some() {
        let path_to_encryption_parameters = boxed_path_to_encryption_parameters.unwrap();
        return [path_to_encryption_parameters, filename].join("");
    }

    filename.to_string()
}


fn read_or_create_and_write(path: &str, content: &str) -> Result<String, String> {
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

fn create_file(path: &str) -> Result<File, String>  {
    let boxed_file = File::create(path);

    if boxed_file.is_err() {
        let message = format!("unable to create file: {}", boxed_file.err().unwrap());
        return Err(message)
    }

    let file = boxed_file.unwrap();
    Ok(file)
}

fn does_file_exist(path: &str) -> bool {
    let file_exists = Path::new(path).is_file();
    file_exists
}

fn read_file(path: &str) -> Result<String, String> {
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

fn write_file(path: &str, file_content: &[u8]) -> Result<(), String> {
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