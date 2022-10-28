use std::{env, fs};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use sha256::digest;
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::sign::{Signer};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;

#[cfg(test)]
mod tests;

pub const DSA_SIZE: u32 = 4096;

pub fn sign(private_key: &str, passphrase: &str, data: &[u8]) -> String {
    //TODO:
    "".to_string()
}

pub fn verify(public_key: &str, data: &[u8], signature: &str) -> bool {
    //TODO
    false
}
