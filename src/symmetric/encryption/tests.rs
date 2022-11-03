use openssl::symm::{encrypt, Cipher};
use crate::generate_passphrase;

#[test]
fn encryption() {
    let data = "some test text";
    let key = generate_passphrase().unwrap();
}