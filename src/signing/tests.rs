use std::fs;
use openssl::bn::BigNumRef;
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};


#[test]
fn signing() {
    let data = "c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0c29tZSB0ZXh0";


    let dsa_ref = Dsa::generate(4096).unwrap();
    let p = dsa_ref.p();
    let q = dsa_ref.q();
    let g = dsa_ref.g();

    let public_key = dsa_ref.pub_key();
    let private_key = dsa_ref.priv_key();

    println!("p: {}", p);
    println!("q: {}", q);
    println!("g: {}", g);
    println!("private_key: {}", private_key);
    println!("public_key: {}", public_key);

    let private_key = Dsa::from_private_components(
        BigNumRef::to_owned(p).unwrap(),
        BigNumRef::to_owned(q).unwrap(),
        BigNumRef::to_owned(g).unwrap(),
        BigNumRef::to_owned(private_key).unwrap(),
        BigNumRef::to_owned(public_key).unwrap(),
    ).unwrap();

    let private_key_pem = private_key.private_key_to_pem().unwrap();
    let public_key_pem = private_key.public_key_to_pem().unwrap();


    let private_key = PKey::from_dsa(private_key).unwrap();

    let public_key = Dsa::from_public_components(
        BigNumRef::to_owned(p).unwrap(),
        BigNumRef::to_owned(q).unwrap(),
        BigNumRef::to_owned(g).unwrap(),
        BigNumRef::to_owned(public_key).unwrap(),
    ).unwrap();

    let public_key = PKey::from_dsa(public_key).unwrap();


    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(data.as_bytes()).unwrap();

    let signature = signer.sign_to_vec().unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(data.as_bytes()).unwrap();

    assert!(verifier.verify(signature.as_ref()).unwrap())

    //TODO:
}