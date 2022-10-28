use std::fs;
use openssl::bn::BigNumRef;
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use crate::encryption::{decrypt, encrypt, setup_encryption};

#[test]
fn encryption() {
    // path needs to be accessible by user with write permission for initial setup
    let relative_path_to_working_directory_for_storing_encryption_parameters = "/test/encryption_parameters/";
    // it will read encryption params like public, private keys and passphrase or create them
    let params = setup_encryption(Some(relative_path_to_working_directory_for_storing_encryption_parameters)).unwrap();

    //maximum 501 bytes at once to be encrypted
    let data = "Some random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomeeSome random textSome random textSome random textSome random textSome random textSome random textSome random textSomee123textSomee123textSomee123textSo";
    println!("data len: {}", data.as_bytes().len());
    let encrypted_u8 = encrypt(params.public_key.as_str(), data.as_bytes());

    let decrypted_u8 = decrypt(params.private_key.as_str(), params.passphrase.as_str(), encrypted_u8.as_ref());

    let decrypted = String::from_utf8(decrypted_u8).unwrap();

    assert_eq!(data.to_string(), decrypted.replace('\0', ""));
}
