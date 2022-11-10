# Welcome to crypto-ext!

Hi, `crypto-ext` is a set of functionality providing easy and intuitive abstractions to encrypt, decrypt, sign and verify your data.

## Features
1. [Asymmetric cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) via [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
1. [Symmetric cryptography](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) via [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
1. [Digital signature](https://en.wikipedia.org/wiki/Digital_signature) via [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
1. [Passphrase](https://en.wikipedia.org/wiki/Passphrase)

## Configuration
To run tests locally you need to create folders _test/encryption_parameters_ and _test/signature_parameters_ in project root folder.

## Demo
[Tests](https://github.com/bohdaq/crypto-ext) are available in the repository.

## Documentation
Public functions definitions and usage can be found at [docs.rs](https://docs.rs/crypto-ext/0.0.1/crypto_ext/).


## Crate
[Link to crate release](https://crates.io/crates/crypto-ext).

## Build
If you want to build `crypto-ext` on your own, make sure you have [Rust installed](https://www.rust-lang.org/tools/install).

> $ cargo build


## Test
If you want to test `crypto-ext`.

> $ cargo test

## Examples 
From documentation:

1. [Asymmetric encryption using public and private keys.](https://docs.rs/crypto-ext/0.0.1/crypto_ext/asymmetric/encryption/fn.encrypt.html)
2. [Symmetric encryption using shared key and nonce.](https://docs.rs/crypto-ext/0.0.1/crypto_ext/symmetric/encryption/fn.encrypt.html)
3. [Electronic signature and verification.](https://docs.rs/crypto-ext/0.0.1/crypto_ext/asymmetric/signing/fn.sign.html)
4. [Generating random passphrase.](https://docs.rs/crypto-ext/0.0.1/crypto_ext/passphrase/fn.generate_passphrase.html)

## Community
Server on [Discord](https://discord.gg/PNqtG5ctMh) where you can ask questions and share ideas. Follow the [Rust code of conduct](https://www.rust-lang.org/policies/code-of-conduct).

## Donations
If you appreciate my work and want to support it, feel free to do it via [PayPal](https://www.paypal.com/donate/?hosted_button_id=VN8QMM52PM6JC).
