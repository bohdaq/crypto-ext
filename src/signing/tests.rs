use crate::signing::{get_signature_params, get_verification_params, setup, sign, verify};


#[test]
fn signing() {
    let data = "c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0";
    let path_to_params = "/test/signature_parameters/";

    // setup will read, or populate required parameters for signing and verification
    // in this example setup is used to populate the required parameters
    let _ = setup(Some(path_to_params)).unwrap();

    let signature_params = get_signature_params(Some(path_to_params)).unwrap();
    let signature = sign(signature_params, data.as_bytes()).unwrap();

    let verification_params = get_verification_params(Some(path_to_params)).unwrap();
    let is_verified = verify(verification_params, data.as_bytes(), signature).unwrap();

    assert!(is_verified);
}

#[test]
fn signing_alternative() {
    let data = "c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0";
    let path_to_params = "/test/signature_parameters/";

    let (signature_params, verification_params) = setup(Some(path_to_params)).unwrap();

    let signature = sign(signature_params, data.as_bytes()).unwrap();

    let is_verified = verify(verification_params, data.as_bytes(), signature).unwrap();

    assert!(is_verified);
}