use crate::symmetric::encryption::{decrypt, encrypt, setup};

#[test]
fn encryption() {
    let data = "some data to encrypt".as_bytes();
    let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker".as_bytes();
    let params_path = "/test/encryption_parameters/";


    let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();

    let encrypted_data = encrypt(encryption_params, data, associated_data).unwrap();

    let decrypted = decrypt(decryption_params, encrypted_data.as_slice(), associated_data).unwrap();

    assert_eq!(data, decrypted);

}