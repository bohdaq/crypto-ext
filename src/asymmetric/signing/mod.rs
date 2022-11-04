use openssl::bn::{BigNum};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::{Signer, Verifier};
use crate::{get_path_relative_to_working_directory, get_static_filepath, read_file, read_or_create_and_write};

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

pub struct VerificationParameters {
    pub dsa_p : String,
    pub dsa_q : String,
    pub dsa_g : String,
    pub dsa_public_key : String,
}

pub fn setup(path_to_encryption_parameters: Option<&str>) -> Result<(SignatureParameters, VerificationParameters), String> {
    let dsa_ref = Dsa::generate(DSA_SIZE).unwrap();

    let (dsa_p,dsa_q,dsa_g, dsa_public_key) = setup_public_components(&dsa_ref, path_to_encryption_parameters).unwrap();
    let dsa_private_key = setup_private_key(&dsa_ref, path_to_encryption_parameters).unwrap();
    let signature_parameters = SignatureParameters {
        dsa_p,
        dsa_q,
        dsa_g,
        dsa_private_key,
        dsa_public_key,
    };

    let (dsa_p,dsa_q,dsa_g, dsa_public_key) = setup_public_components(&dsa_ref, path_to_encryption_parameters).unwrap();
    let verification_parameters = VerificationParameters {
        dsa_p,
        dsa_q,
        dsa_g,
        dsa_public_key,
    };

    Ok((signature_parameters, verification_parameters))
}

pub fn get_signature_params(path_to_encryption_parameters: Option<&str>) -> Result<SignatureParameters, String> {
    let dsa_private_key = get_private_key(path_to_encryption_parameters).unwrap();
    let (dsa_p, dsa_q, dsa_g, dsa_public_key ) = get_public_components(path_to_encryption_parameters).unwrap();
    let params = SignatureParameters {
        dsa_p,
        dsa_q,
        dsa_g,
        dsa_private_key,
        dsa_public_key,
    };

    Ok(params)
}

pub fn get_verification_params(path_to_encryption_parameters: Option<&str>) -> Result<VerificationParameters, String> {
    let (dsa_p, dsa_q, dsa_g, dsa_public_key ) = get_public_components(path_to_encryption_parameters).unwrap();
    let params = VerificationParameters {
        dsa_p,
        dsa_q,
        dsa_g,
        dsa_public_key,
    };

    Ok(params)
}

pub fn sign(params: SignatureParameters, data: &[u8]) -> Result<Vec<u8>, String> {
    let boxed_private_key = get_big_number(params.dsa_private_key.as_str());
    if boxed_private_key.is_err() {
        let message = boxed_private_key.err().unwrap().to_string();
        return Err(message)
    }
    let private_key = boxed_private_key.unwrap();

    let boxed_public_key = get_big_number(params.dsa_public_key.as_str());
    if boxed_public_key.is_err() {
        let message = boxed_public_key.err().unwrap().to_string();
        return Err(message)
    }
    let public_key= boxed_public_key.unwrap();

    let boxed_p = get_big_number(params.dsa_p.as_str());
    if boxed_p.is_err() {
        let message = boxed_p.err().unwrap().to_string();
        return Err(message)
    }
    let p = boxed_p.unwrap();

    let boxed_q = get_big_number(params.dsa_q.as_str());
    if boxed_q.is_err() {
        let message = boxed_q.err().unwrap().to_string();
        return Err(message)
    }
    let q = boxed_q.unwrap();

    let boxed_g = get_big_number(params.dsa_g.as_str());
    if boxed_g.is_err() {
        let message = boxed_g.err().unwrap().to_string();
        return Err(message)
    }
    let g = boxed_g.unwrap();

    let boxed_dsa_private = Dsa::from_private_components(p, q, g, private_key, public_key);
    let dsa_private = boxed_dsa_private.unwrap();

    let boxed_pkey_private = PKey::from_dsa(dsa_private);
    if boxed_pkey_private.is_err() {
        let message = boxed_pkey_private.err().unwrap().to_string();
        return Err(message)
    }
    let pkey_private = boxed_pkey_private.unwrap();

    let boxed_signer = Signer::new(MessageDigest::sha256(), &pkey_private);
    if boxed_signer.is_err() {
        let message = boxed_signer.err().unwrap().to_string();
        return Err(message)
    }
    let mut signer = boxed_signer.unwrap();

    let boxed_update = signer.update(data);
    if boxed_update.is_err() {
        let message = boxed_update.err().unwrap().to_string();
        return Err(message)
    }
    boxed_update.unwrap();

    let boxed_signature_to_vec = signer.sign_to_vec();
    if boxed_signature_to_vec.is_err() {
        let message = boxed_signature_to_vec.err().unwrap().to_string();
        return Err(message)
    }
    let signature = boxed_signature_to_vec.unwrap();
    Ok(signature)
}

pub fn verify(params: VerificationParameters, data: &[u8], signature: Vec<u8>) -> Result<bool, String> {
    let boxed_public_key = get_big_number(params.dsa_public_key.as_str());
    if boxed_public_key.is_err() {
        let message = boxed_public_key.err().unwrap().to_string();
        return Err(message)
    }
    let public_key= boxed_public_key.unwrap();

    let boxed_p = get_big_number(params.dsa_p.as_str());
    if boxed_p.is_err() {
        let message = boxed_p.err().unwrap().to_string();
        return Err(message)
    }
    let p = boxed_p.unwrap();

    let boxed_q = get_big_number(params.dsa_q.as_str());
    if boxed_q.is_err() {
        let message = boxed_q.err().unwrap().to_string();
        return Err(message)
    }
    let q = boxed_q.unwrap();

    let boxed_g = get_big_number(params.dsa_g.as_str());
    if boxed_g.is_err() {
        let message = boxed_g.err().unwrap().to_string();
        return Err(message)
    }
    let g = boxed_g.unwrap();

    let boxed_dsa = Dsa::from_public_components(
        p,
        q,
        g,
        public_key,
    );
    if boxed_dsa.is_err() {
        let message = boxed_dsa.err().unwrap().to_string();
        return Err(message)
    }
    let dsa_public = boxed_dsa.unwrap();

    let boxed_pkey_public = PKey::from_dsa(dsa_public);
    if boxed_pkey_public.is_err() {
        let message = boxed_pkey_public.err().unwrap().to_string();
        return Err(message)
    }
    let public_key = boxed_pkey_public.unwrap();

    let boxed_verifier = Verifier::new(MessageDigest::sha256(), &public_key);
    if boxed_verifier.is_err() {
        let message = boxed_verifier.err().unwrap().to_string();
        return Err(message)
    }
    let mut verifier = boxed_verifier.unwrap();

    let boxed_update = verifier.update(data);
    if boxed_update.is_err() {
        let message = boxed_update.err().unwrap().to_string();
        return Err(message)
    }
    boxed_update.unwrap();

    let boxed_verify = verifier.verify(signature.as_ref());
    if boxed_verify.is_err() {
        let message = boxed_verify.err().unwrap().to_string();
        return Err(message)
    }
    let is_verified = boxed_verify.unwrap();

    Ok(is_verified)
}

// below are functions not exposed as an api, used for inner implementation

fn get_big_number(number: &str) -> Result<BigNum, String> {
    let boxed_big_number = BigNum::from_dec_str(number);
    if boxed_big_number.is_err() {
        let message = boxed_big_number.err().unwrap().to_string();
        return Err(message)
    }
    let big_number = boxed_big_number.unwrap();
    Ok(big_number)
}

fn setup_private_key(dsa_ref: &Dsa<Private>, path_to_encryption_parameters: Option<&str>) -> Result<String, String> {
    let private_key = dsa_ref.priv_key();

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_private_key");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }

    let dsa_private_key_path = boxed_private_key_path.unwrap();
    let boxed_private_key = get_or_create_value_at_path(dsa_private_key_path.as_str(), private_key.to_string().as_str());
    if boxed_private_key.is_err() {
        return Err(boxed_private_key.err().unwrap());
    }
    let private_key = boxed_private_key.unwrap();
    Ok(private_key)
}

fn get_private_key(path_to_encryption_parameters: Option<&str>) -> Result<String, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_private_key");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }

    let dsa_private_key_path = boxed_private_key_path.unwrap();
    let boxed_private_key = read_file(dsa_private_key_path.as_str());
    if boxed_private_key.is_err() {
        return Err(boxed_private_key.err().unwrap());
    }
    let private_key = boxed_private_key.unwrap();
    Ok(private_key)
}

fn setup_public_components(dsa_ref: &Dsa<Private>, path_to_encryption_parameters: Option<&str>) -> Result<(String, String, String, String), String> {
    let p = dsa_ref.p();
    let q = dsa_ref.q();
    let g = dsa_ref.g();

    let public_key = dsa_ref.pub_key();

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

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_g");
    let boxed_dsa_g_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_g_path.is_err() {
        return Err(boxed_dsa_g_path.err().unwrap());
    }

    let dsa_q_path = boxed_dsa_g_path.unwrap();
    let boxed_g = get_or_create_value_at_path(dsa_q_path.as_str(), g.to_string().as_str());
    if boxed_g.is_err() {
        return Err(boxed_g.err().unwrap());
    }

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_public_key");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }

    let dsa_public_key_path = boxed_public_key_path.unwrap();
    let boxed_public_key = get_or_create_value_at_path(dsa_public_key_path.as_str(), public_key.to_string().as_str());
    if boxed_public_key.is_err() {
        return Err(boxed_public_key.err().unwrap());
    }

    let p = boxed_p.unwrap();
    let q = boxed_q.unwrap();
    let g = boxed_g.unwrap();
    let public_key = boxed_public_key.unwrap();

    Ok((p, q, g, public_key))
}

fn get_public_components(path_to_encryption_parameters: Option<&str>) -> Result<(String, String, String, String), String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_p");
    let boxed_dsa_p_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_p_path.is_err() {
        return Err(boxed_dsa_p_path.err().unwrap());
    }

    let dsa_p_path = boxed_dsa_p_path.unwrap();
    let boxed_p = read_file(dsa_p_path.as_str());
    if boxed_p.is_err() {
        return Err(boxed_p.err().unwrap());
    }


    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_q");
    let boxed_dsa_q_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_q_path.is_err() {
        return Err(boxed_dsa_q_path.err().unwrap());
    }

    let dsa_q_path = boxed_dsa_q_path.unwrap();
    let boxed_q = read_file(dsa_q_path.as_str());
    if boxed_q.is_err() {
        return Err(boxed_q.err().unwrap());
    }

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_g");
    let boxed_dsa_g_path = get_static_filepath(relative_path.as_str());
    if boxed_dsa_g_path.is_err() {
        return Err(boxed_dsa_g_path.err().unwrap());
    }

    let dsa_q_path = boxed_dsa_g_path.unwrap();
    let boxed_g = read_file(dsa_q_path.as_str());
    if boxed_g.is_err() {
        return Err(boxed_g.err().unwrap());
    }

    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".dsa_public_key");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }

    let dsa_public_key_path = boxed_public_key_path.unwrap();
    let boxed_public_key = read_file(dsa_public_key_path.as_str());
    if boxed_public_key.is_err() {
        return Err(boxed_public_key.err().unwrap());
    }

    let p = boxed_p.unwrap();
    let q = boxed_q.unwrap();
    let g = boxed_g.unwrap();
    let public_key = boxed_public_key.unwrap();

    Ok((p, q, g, public_key))
}

fn get_or_create_value_at_path(path: &str, value: &str) -> Result<String, String> {

    let boxed_passphrase = read_or_create_and_write(path, value);
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();
    Ok(passphrase)
}