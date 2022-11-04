use crate::generate_passphrase;
use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use crate::symmetric::encryption::{encrypt, EncryptionParameters};

#[test]
fn encryption() {
    let data = "some data to encrypt";
    let associated_data = "some unencrypted data that needs to be sent along the encrypted data and won't be changed during transmission by a hacker";

    let passphrase_64_bytes = generate_passphrase().unwrap();

    // key is 16 bytes long
    let key = passphrase_64_bytes[48..64].to_string();

    // nonce is 12 bytes long
    let nonce = passphrase_64_bytes[36..48].to_string();

    let params = EncryptionParameters {
        key,
        nonce,
    };
    let cipher_text = encrypt(params, data.as_bytes(), associated_data.as_bytes()).unwrap();

    // decryption

    let payload = Payload {
        msg: &cipher_text,
        aad: associated_data.as_bytes(),
    };

    let key = passphrase_64_bytes[48..64].to_string();
    let nonce = passphrase_64_bytes[36..48].to_string();

    let key = GenericArray::from_slice(key.as_bytes());
    let nonce = GenericArray::from_slice(nonce.as_bytes());
    let cipher = Aes128Gcm::new(key);
    let plain_text = cipher.decrypt(nonce, payload).unwrap();

    assert_eq!(data.as_bytes(), plain_text);

}