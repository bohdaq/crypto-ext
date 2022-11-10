use crate::symmetric::encryption::{decrypt, encrypt, get_decryption_params, get_encryption_params, setup};

#[test]
fn encryption() {
    let data = "some data to encrypt".as_bytes();
    let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker".as_bytes();

    // path needs to be accessible by user with write permission for initial setup
    // ideally for each encryption you need to setup unique folder for AES key and nonce
    // do not reuse same setup with Encryption and Decryption parameters for multiple encryptions
    let params_path = "/test/encryption_parameters/";


    let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();

    let encrypted_data = encrypt(encryption_params, data, associated_data).unwrap();

    let decrypted = decrypt(decryption_params, encrypted_data.as_slice(), associated_data).unwrap();

    assert_eq!(data, decrypted);

}

#[test]
fn decryption() {
    // to decrypt we need to encrypt first
    let data = "some data to encrypt".as_bytes();
    let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker".as_bytes();

    // path needs to be accessible by user with write permission for initial setup
    // ideally for each encryption you need to setup unique folder for AES key and nonce
    // do not reuse same setup with Encryption and Decryption parameters for multiple encryptions
    let params_path = "/test/encryption_parameters/";


    let _ = setup(Some(params_path)).unwrap();

    let encryption_params = get_encryption_params(Some(params_path)).unwrap();
    let encrypted_data = encrypt(encryption_params, data, associated_data).unwrap();

    let decryption_params = get_decryption_params(Some(params_path)).unwrap();
    let decrypted = decrypt(decryption_params, encrypted_data.as_slice(), associated_data).unwrap();

    assert_eq!(data, decrypted);

}