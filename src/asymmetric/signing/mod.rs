use crate::{get_path_relative_to_working_directory, get_static_filepath, read_file, read_or_create_and_write};
use p256::{ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier}, EncodedPoint};
use aes_gcm::aead::rand_core::OsRng;

#[cfg(test)]
mod tests;

/// SignatureParameters is basically the .der encoded ECDSA private key
pub struct SignatureParameters {
    pub ecdsa_private_key: Vec<u8>,
}

/// VerificationParameters is basically the .der encoded ECDSA public key
pub struct VerificationParameters {
    pub ecdsa_public_key: Vec<u8>,
}

/// Will read or create SignatureParameters and VerificationParameters at the given location which is relative to the working directory
pub fn setup(path_to_encryption_parameters: Option<&str>) -> Result<(SignatureParameters, VerificationParameters), String> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let signing_key_as_bytes = Vec::from(signing_key.to_bytes().as_slice());
    let verifying_key_as_bytes = Vec::from(verifying_key.to_encoded_point(false).as_bytes());

    let ecdsa_private_key = setup_private_key(signing_key_as_bytes.as_slice(), path_to_encryption_parameters).unwrap();
    let ecdsa_public_key = setup_public_key(verifying_key_as_bytes.as_slice(), path_to_encryption_parameters).unwrap();

    let signature_parameters = SignatureParameters {
        ecdsa_private_key
    };

    let verification_parameters = VerificationParameters {
        ecdsa_public_key
    };

    Ok((signature_parameters, verification_parameters))
}

/// Returns SignatureParameters stored at the given location which is relative to the working directory
pub fn get_signature_params(path_to_encryption_parameters: Option<&str>) -> Result<SignatureParameters, String> {
    let ecdsa_private_key = get_private_key(path_to_encryption_parameters).unwrap();
        let params = SignatureParameters {
        ecdsa_private_key,
    };

    Ok(params)
}

/// Returns VerificationParameters stored at the given location which is relative to the working directory
pub fn get_verification_params(path_to_encryption_parameters: Option<&str>) -> Result<VerificationParameters, String> {
    let ecdsa_public_key = get_public_key(path_to_encryption_parameters).unwrap();
    let params = VerificationParameters {
        ecdsa_public_key
    };

    Ok(params)
}

/// Signs given byte array
///
/// # Examples
///
/// ```
///     use crypto_ext::asymmetric::signing::{get_signature_params, get_verification_params, setup, sign, verify};
///     #[test]
///     fn signing() {
///         let data = "some data to sign".as_bytes();
///         // path needs to be accessible by user with write permission for initial setup
///         let path_to_params = "/test/signature_parameters/";
///
///         // setup will read, or populate required parameters for signing and verification
///         // in this example setup is used to populate the required parameters
///         let (signature_params, verification_params) = setup(Some(path_to_params)).unwrap();
///
///         let signature = sign(signature_params, data).unwrap();
///
///         let verified = verify(verification_params, data, signature.as_slice());
///
///         assert!(verified.is_ok());
///     }
/// ```
pub fn sign(params: SignatureParameters, data: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_bytes(params.ecdsa_private_key.as_slice()).unwrap();
    let signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}


/// Verifies given byte array
///
/// # Examples
///
///
/// ```
///     use crypto_ext::asymmetric::signing::{get_signature_params, get_verification_params, setup, sign, verify};
///     #[test]
///     fn verification() {
///         let data = "some data to sign".as_bytes();
///         let path_to_params = "/test/signature_parameters/";
///
///         // to verify signature, we need to sign first
///         // setup will read, or populate required parameters for signing and verification
///         // in this example setup is used to populate the required parameters
///         let _ = setup(Some(path_to_params)).unwrap();
///
///         let signature_params = get_signature_params(Some(path_to_params)).unwrap();
///         let signature = sign(signature_params, data).unwrap();
///
///         let verification_params = get_verification_params(Some(path_to_params)).unwrap();
///         let verified = verify(verification_params, data, signature.as_slice());
///
///         assert!(verified.is_ok());
///     }
/// ```
pub fn verify(params: VerificationParameters, data: &[u8], signature: &[u8]) -> Result<(), String> {
    let point = EncodedPoint::from_bytes(params.ecdsa_public_key.as_slice()).unwrap();
    let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();

    let signature = Signature::from_der(signature).unwrap();
    let verified = verifying_key.verify(data, &signature);

    return if verified.is_ok() {
        Ok(())
    } else {
        let message = verified.err().unwrap().to_string();
        Err(message)
    }
}

// below are functions not exposed as an api, used for inner implementation

fn setup_private_key(private_key: &[u8], path_to_encryption_parameters: Option<&str>) -> Result<Vec<u8>, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".ecdsa_private_key.der");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }

    let dsa_private_key_path = boxed_private_key_path.unwrap();
    let boxed_private_key = get_or_create_value_at_path(dsa_private_key_path.as_str(), private_key);
    if boxed_private_key.is_err() {
        return Err(boxed_private_key.err().unwrap());
    }
    let private_key = boxed_private_key.unwrap();
    Ok(private_key)
}

fn get_private_key(path_to_encryption_parameters: Option<&str>) -> Result<Vec<u8>, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".ecdsa_private_key.der");
    let boxed_private_key_path = get_static_filepath(relative_path.as_str());
    if boxed_private_key_path.is_err() {
        return Err(boxed_private_key_path.err().unwrap());
    }

    let ecdsa_private_key_path = boxed_private_key_path.unwrap();
    let boxed_private_key = read_file(ecdsa_private_key_path.as_str());
    if boxed_private_key.is_err() {
        return Err(boxed_private_key.err().unwrap());
    }
    let private_key = boxed_private_key.unwrap();
    Ok(private_key)
}

fn setup_public_key(public_key: &[u8], path_to_encryption_parameters: Option<&str>) -> Result<Vec<u8>, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".ecdsa_public_key.der");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }

    let ecdsa_public_key_path = boxed_public_key_path.unwrap();
    let boxed_public_key = get_or_create_value_at_path(ecdsa_public_key_path.as_str(), public_key);
    if boxed_public_key.is_err() {
        return Err(boxed_public_key.err().unwrap());
    }

    let public_key = boxed_public_key.unwrap();

    Ok(public_key)
}

fn get_public_key(path_to_encryption_parameters: Option<&str>) -> Result<Vec<u8>, String> {
    let relative_path = get_path_relative_to_working_directory(path_to_encryption_parameters, ".ecdsa_public_key.der");
    let boxed_public_key_path = get_static_filepath(relative_path.as_str());
    if boxed_public_key_path.is_err() {
        return Err(boxed_public_key_path.err().unwrap());
    }

    let ecdsa_public_key_path = boxed_public_key_path.unwrap();
    let boxed_public_key = read_file(ecdsa_public_key_path.as_str());
    if boxed_public_key.is_err() {
        return Err(boxed_public_key.err().unwrap());
    }

    let public_key = boxed_public_key.unwrap();

    Ok(public_key)
}

fn get_or_create_value_at_path(path: &str, value: &[u8]) -> Result<Vec<u8>, String> {

    let boxed_passphrase = read_or_create_and_write(path, value);
    if boxed_passphrase.is_err() {
        let message = boxed_passphrase.err().unwrap();
        return Err(message)
    }

    let passphrase = boxed_passphrase.unwrap();
    Ok(passphrase)
}
