use aes_gcm::aead::rand_core::OsRng;
use crate::asymmetric::signing::{get_signature_params, get_verification_params, setup, sign, verify};
use p256:: {
    ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier},
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
    let is_verified = verify(verification_params, data, signature).unwrap();

    assert!(is_verified);
}

#[test]
fn signing_alternative() {
    let data = "some data to sign".as_bytes();
    let path_to_params = "/test/signature_parameters/";

    let (signature_params, verification_params) = setup(Some(path_to_params)).unwrap();

    let signature = sign(signature_params, data).unwrap();

    let is_verified = verify(verification_params, data, signature).unwrap();

    assert!(is_verified);
}

#[test]
fn ecdsa() {
    let signing_key = SigningKey::random(&mut OsRng);
    let data = "data to sign".as_bytes();
    let signature = signing_key.sign(data);

    let verifying_key = VerifyingKey::from(&signing_key);
    let boxed_verify = verifying_key.verify(data, &signature);

    assert!(boxed_verify.is_ok());
}