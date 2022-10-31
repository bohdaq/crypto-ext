use crate::signing::{setup_signature, setup_verification, sign, verify};


#[test]
fn signing() {
    let data = "c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0";

    let signature_params = setup_signature(Some("/test/signature_parameters/")).unwrap();
    let signature = sign(signature_params, data.as_bytes()).unwrap();

    let verification_params = setup_verification(Some("/test/signature_parameters/")).unwrap();
    let is_verified = verify(verification_params, data.as_bytes(), signature).unwrap();
    assert!(is_verified);
}