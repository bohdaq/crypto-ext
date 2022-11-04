use crate::generate_passphrase;
use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

#[test]
fn encryption() {
    let data = "some test text".to_string();

    let key = generate_passphrase().unwrap();

    let nonce = generate_passphrase().unwrap();

    let aad = "";

    let payload = Payload {
        msg: data.as_bytes(),
        aad: aad.as_bytes(),
    };

    let key = GenericArray::from_slice(key[48..64].as_bytes());
    let nonce = GenericArray::from_slice(nonce[36..48].as_bytes());

    let cipher = Aes128Gcm::new(key);

    let cipher_text = cipher.encrypt(nonce, payload).unwrap();
    let (_ct, _tag) = cipher_text.split_at(cipher_text.len() - 16);

    let payload = Payload {
        msg: &cipher_text,
        aad: aad.as_bytes(),
    };

    let plain_text = cipher.decrypt(nonce, payload).unwrap();

    assert_eq!(data.as_bytes(), plain_text);

}