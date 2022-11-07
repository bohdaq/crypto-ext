use aes_gcm::aead::rand_core::OsRng;
use crate::asymmetric::signing::{get_signature_params, get_verification_params, setup, sign, verify};
use p256:: {
    ecdsa::{SigningKey, signature::Signer, VerifyingKey, signature::Verifier},
};



#[test]
fn signing() {
    let data = "some data to sign".as_bytes();
    let path_to_params = "/test/signature_parameters/";

    // setup will read, or populate required parameters for signing and verification
    // in this example setup is used to populate the required parameters
    let _ = setup(Some(path_to_params)).unwrap();

    let signature_params = get_signature_params(Some(path_to_params)).unwrap();
    let signature = sign(signature_params, data).unwrap();

    let verification_params = get_verification_params(Some(path_to_params)).unwrap();
    let verified = verify(verification_params, data, signature.as_slice());

    assert!(verified.is_ok());
}

#[test]
fn signing_alternative() {
    let data = "some data to sign".as_bytes();
    let path_to_params = "/test/signature_parameters/";

    let (signature_params, verification_params) = setup(Some(path_to_params)).unwrap();

    let signature = sign(signature_params, data).unwrap();

    let verified = verify(verification_params, data, signature.as_slice());

    assert!(verified.is_ok());
}