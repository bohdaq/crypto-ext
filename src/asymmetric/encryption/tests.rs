use crate::asymmetric::encryption::{decrypt, encrypt, get_decryption_params, get_encryption_params, setup};

#[test]
fn encryption() {
    //maximum 501 bytes at once to be encrypted
    let data_to_encrypt_as_bytes = "Some data to encrypt".as_bytes();

    // path needs to be accessible by user with write permission for initial setup
    let params_path = "/test/encryption_parameters/";
    // it will read encryption params like public, private keys and passphrase or create them
    // in this example setup is used to populate the params and used later via get_encryption_params or get_decryption_params
    let _ = setup(Some(params_path));

    let encryption_params  = get_encryption_params(Some(params_path)).unwrap();
    let encrypted_bytes = encrypt(encryption_params, data_to_encrypt_as_bytes).unwrap();

    let decryption_params = get_decryption_params(Some(params_path)).unwrap();
    let decrypted_bytes = decrypt(decryption_params, encrypted_bytes.as_slice()).unwrap();

    assert_eq!(data_to_encrypt_as_bytes, decrypted_bytes);
}

#[test]
fn encryption_alternative() {
    // maximum 501 bytes at once to be encrypted
    let data_to_encrypt_as_bytes = "Some data to encrypt".as_bytes();

    // path needs to be accessible by user with write permission for initial setup
    let params_path = "/test/encryption_parameters/";
    // this will create encryption params like public, private keys and passphrase
    let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();

    let encrypted_bytes = encrypt(encryption_params, data_to_encrypt_as_bytes).unwrap();
    let decrypted_bytes = decrypt(decryption_params, encrypted_bytes.as_slice()).unwrap();

    assert_eq!(data_to_encrypt_as_bytes, decrypted_bytes);
}
