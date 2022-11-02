use crate::asymmetric::encryption::{decrypt, encrypt, get_decryption_params, get_encryption_params, setup};

#[test]
fn encryption() {
    //maximum 501 bytes at once to be encrypted
    let data = "Some random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomee123textSomee123textSomee123textSo";
    println!("data len: {}", data.as_bytes().len());
    
    // path needs to be accessible by user with write permission for initial setup
    let params_path = "/test/encryption_parameters/";
    // it will read encryption params like public, private keys and passphrase or create them
    // in this example setup is used to populate the params and used later via get_encryption_params or get_decryption_params
    let _ = setup(Some(params_path));

    let params  = get_encryption_params(Some(params_path)).unwrap();
    let encrypted_u8 = encrypt(params, data.as_bytes()).unwrap();

    let params = get_decryption_params(Some(params_path)).unwrap();
    let decrypted_u8 = decrypt(params, encrypted_u8.as_ref()).unwrap();

    let decrypted = String::from_utf8(decrypted_u8).unwrap();

    //decrypted data will contain trailing \0, removing them
    assert_eq!(data.to_string(), decrypted.replace('\0', ""));
}

#[test]
fn encryption_alternative() {
    let data = "Some random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomee123textSomee123textSomee123textSo";
    // maximum 501 bytes at once to be encrypted
    println!("data len: {}", data.as_bytes().len());

    // path needs to be accessible by user with write permission for initial setup
    let params_path = "/test/encryption_parameters/";
    // this will create encryption params like public, private keys and passphrase
    let (encryption_params, decryption_params) = setup(Some(params_path)).unwrap();


    let encrypted_vec_u8 = encrypt(encryption_params, data.as_bytes()).unwrap();
    let decrypted_vec_u8 = decrypt(decryption_params, encrypted_vec_u8.as_ref()).unwrap();

    let decrypted = String::from_utf8(decrypted_vec_u8).unwrap();

    //decrypted data will contain trailing \0, removing them
    assert_eq!(data.to_string(), decrypted.replace('\0', ""));
}
