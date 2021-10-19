use std::fs::File;
use std::io::prelude::*;
use ring::digest;
use std::num::NonZeroU32;
use ring::rand;
use ring::rand::SecureRandom;
use ring::pbkdf2;

fn encode_password(password: &str) -> String {
    base64::encode(password)
}
fn decode_password(encoded: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode(encoded)
}

fn save_master_password(master_password: &[u8]) -> std::io::Result<()> {
    let mut file = File::create("password.txt")?;
    file.write_all(master_password)?;
    Ok(())
}

fn main() {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let rng = rand::SystemRandom::new();

    let mut salt = [0u8; CREDENTIAL_LEN];
    match rng.fill(&mut salt) {
        Ok(_) => {},
        Err(_) => panic!("Cannot generate salt"),
    }

    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password).unwrap();
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );

    let mut file = File::open("master_password.txt");
}

#[test]
fn test_encoding() {
    assert_eq!(false, encode_password("password").is_empty());
}

#[test]
fn test_decoding() {
    let coded = b"cGFzc3dvcmQ=";
    assert_eq!(&decode_password(coded).unwrap()[..], b"password");
}

#[test]
fn test_save_master_password() -> std::io::Result<()> {
    save_master_password(b"master_password")
}
