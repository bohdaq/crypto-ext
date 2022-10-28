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

pub mod encryption;
pub mod signing;