use crate::generate_passphrase;
use crate::symmetric::encryption::{decrypt, DecryptionParameters, encrypt, EncryptionParameters};

#[test]
fn encryption() {
    let data = "some data to encrypt".as_bytes();
    let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker".as_bytes();

    let passphrase_64_bytes = generate_passphrase().unwrap();

    // key is 16 bytes long
    let key = passphrase_64_bytes[48..64].to_string();

    // nonce is 12 bytes long
    let nonce = passphrase_64_bytes[36..48].to_string();

    let params = EncryptionParameters { key, nonce };
    let encrypted_data = encrypt(params, data, associated_data).unwrap();


    // decryption
    let key = passphrase_64_bytes[48..64].to_string();
    let nonce = passphrase_64_bytes[36..48].to_string();

    let params = DecryptionParameters{ key, nonce };
    let decrypted = decrypt(params, encrypted_data.as_slice(), associated_data).unwrap();

    assert_eq!(data, decrypted);

}