use crate::passphrase::generate_passphrase;

#[test]
fn passphrase() {
    let passphrase = generate_passphrase().unwrap();
    assert_eq!(passphrase.len(), 64);
}