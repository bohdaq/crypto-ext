use openssl::dsa::Dsa;
use crate::encryption::{generate_passphrase, get_path_relative_to_working_directory, get_static_filepath, read_or_create_and_write};

#[cfg(test)]
mod tests;

pub const DSA_SIZE: u32 = 4096;

pub struct SignatureParameters {
    pub dsa_p : String,
    pub dsa_q : String,
    pub dsa_g : String,
    pub dsa_private_key: String,
    pub dsa_public_key : String,
}

pub fn setup_signature(path_to_encryption_parameters: Option<&str>) -> Result<SignatureParameters, String> {
    let dsa_ref = Dsa::generate(DSA_SIZE).unwrap();
    let p = dsa_ref.p();
    let q = dsa_ref.q();
    let g = dsa_ref.g();

    let public_key = dsa_ref.pub_key();
    let private_key = dsa_ref.priv_key();

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_p");
    let boxed_dsa_p_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_p_path.is_err() {
        return Err(boxed_dsa_p_path.err().unwrap());
    }

    let dsa_p_path = boxed_dsa_p_path.unwrap();
    let boxed_p = get_or_create_value_at_path(dsa_p_path.as_str(), p.to_string().as_str());
    if boxed_p.is_err() {
        return Err(boxed_p.err().unwrap());
    }


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_q");
    let boxed_dsa_q_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_q_path.is_err() {
        return Err(boxed_dsa_q_path.err().unwrap());
    }

    let dsa_q_path = boxed_dsa_q_path.unwrap();
    let boxed_q = get_or_create_value_at_path(dsa_q_path.as_str(), q.to_string().as_str());
    if boxed_q.is_err() {
        return Err(boxed_q.err().unwrap());
    }

    let signature_parameters = SignatureParameters{
        dsa_p: boxed_p.unwrap(),
        dsa_q: boxed_q.unwrap(),
        dsa_g: "".to_string(),
        dsa_private_key: "".to_string(),
        dsa_public_key: "".to_string()
    };
    Ok(signature_parameters)
}

pub fn get_or_create_value_at_path(path: &str, value: &str) -> Result<String, String> {

    let boxed_passphrase = read_or_create_and_write(path, value);
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();
    Ok(passphrase)
}

pub fn sign(private_key: &str, passphrase: &str, data: &[u8]) -> String {
    //TODO:
    "".to_string()
}

pub fn verify(public_key: &str, data: &[u8], signature: &str) -> bool {
    //TODO
    false
}
