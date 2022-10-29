use crate::signing::{setup_signature, sign, VerificationParameters, verify};


#[test]
fn signing() {
    let data = "c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0";

    let signature_params = setup_signature(Some("/test/signature_parameters/")).unwrap();
    let signature = sign(signature_params, data.as_bytes());

    let params = setup_signature(Some("/test/signature_parameters/")).unwrap();
    let verification_params = VerificationParameters {
        dsa_p: params.dsa_p,
        dsa_q: params.dsa_q,
        dsa_g: params.dsa_g,
        dsa_public_key: params.dsa_public_key,
    };

    let is_verified = verify(verification_params, data.as_bytes(), signature);
    assert!(is_verified);
}