use crate::encryption::{get_path_relative_to_working_directory, get_static_filepath};

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
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_p");
    let boxed_dsa_p_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_p_path.is_err() {
        return Err(boxed_dsa_p_path.err().unwrap());
    }
    let dsa_p_path = boxed_dsa_p_path.unwrap();
}

pub fn sign(private_key: &str, passphrase: &str, data: &[u8]) -> String {
    //TODO:
    "".to_string()
}

pub fn verify(public_key: &str, data: &[u8], signature: &str) -> bool {
    //TODO
    false
}
