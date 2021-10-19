fn encode_password(password: &str) -> std::result::Result<(), ()> {
    todo!();
}
fn decode_password(encoded: &[u8]) -> std::result::Result<&str, ()> {
    todo!();
}

fn main() {
    println!("Hello, world!");
}

#[test]
fn test_encoding() {
    assert!(encode_password("password").is_ok());
}

#[test]
fn test_decoding() {
    let coded = b"cGFzc3dvcmQ=";
    assert_eq!(decode_password(coded).unwrap(), "password");
}
