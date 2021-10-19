use std::fs::File;
use std::io::prelude::*;

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
    println!("Hello, world!");
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
