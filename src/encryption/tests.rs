use crate::encryption::{decrypt, encrypt, get_decryption_params, get_encryption_params, setup};

#[test]
fn encryption() {
    // path needs to be accessible by user with write permission for initial setup
    let relative_path_to_working_directory_for_storing_encryption_parameters = "/test/encryption_parameters/";
    // it will read encryption params like public, private keys and passphrase or create them
    let _ = setup(Some(relative_path_to_working_directory_for_storing_encryption_parameters));

    let params  = get_encryption_params(Some(relative_path_to_working_directory_for_storing_encryption_parameters)).unwrap();

    //maximum 501 bytes at once to be encrypted
    let data = "Some random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomee123textSomee123textSomee123textSo";
    println!("data len: {}", data.as_bytes().len());
    let encrypted_u8 = encrypt(params, data.as_bytes()).unwrap();

    let params = get_decryption_params(Some(relative_path_to_working_directory_for_storing_encryption_parameters)).unwrap();
    let decrypted_u8 = decrypt(params, encrypted_u8.as_ref()).unwrap();

    let decrypted = String::from_utf8(decrypted_u8).unwrap();

    assert_eq!(data.to_string(), decrypted.replace('\0', ""));
}
