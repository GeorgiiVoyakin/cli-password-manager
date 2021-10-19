use ring::digest;
use ring::error;
use ring::pbkdf2;
use ring::rand;
use ring::rand::SecureRandom;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdin;
use std::num::NonZeroU32;
use std::result;
use std::fs::OpenOptions;

fn encode_password(password: &str) -> String {
    base64::encode(password)
}
fn decode_password(encoded: &[u8]) -> result::Result<Vec<u8>, base64::DecodeError> {
    base64::decode(encoded)
}

fn save_master_password(master_password: &[u8]) -> std::io::Result<()> {
    let mut file = File::create("master_password")?;
    file.write_all(master_password)?;
    Ok(())
}

fn verify_master_password(
    password_to_verify: &str,
    n_iter: NonZeroU32,
    salt: &[u8],
    pbkdf2_hash: &mut [u8],
) -> result::Result<(), error::Unspecified> {
    let mut file = File::open("master_password").expect("Failed to open file");
    let mut secret = String::new();
    file.read_to_string(&mut secret)
        .expect("failed to read from file");
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        salt,
        secret.as_bytes(),
        pbkdf2_hash,
    );
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        salt,
        password_to_verify.as_bytes(),
        pbkdf2_hash,
    )
}

fn main() {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; CREDENTIAL_LEN];
    match rng.fill(&mut salt) {
        Ok(_) => {}
        Err(_) => panic!("Cannot generate salt"),
    }

    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    let mut password = String::new();
    match File::open("master_password") {
        Ok(_) => {
            println!("Enter master password: ");
            std::io::stdin()
                .read_line(&mut password)
                .expect("Failed to read line");

            match verify_master_password(&password, n_iter, &salt, &mut pbkdf2_hash) {
                Ok(_) => {
                    println!("Master password verification succeed");
                    print!("Enter 1 to get passwords, 2 to add new password: ");
                    let mut tmp = String::new();
                    stdin().read_line(&mut tmp).expect("Failed to read line");

                    let opt: u8 = match tmp.trim().parse() {
                        Ok(num) => num,
                        Err(_) => panic!("Failed to parse number"),
                    };

                    if opt == 1 {
                        let f = File::open("passwords.txt").expect("You don't have any passwords");

                        let reader = std::io::BufReader::new(f);

                        for line in reader.lines() {
                            match line {
                                Ok(v) => println!("{}", encode_password(&v)),
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    } else if opt == 2 {
                        let mut passwords = OpenOptions::new()
                            .write(true)
                            .append(true)
                            .open("passwords")
                            .unwrap();

                            let mut new_password = String::new();
                            std::io::stdin()
                            .read_line(&mut new_password)
                            .expect("Failed to read line");

                        

                        if let Err(e) = writeln!(passwords, "{}", new_password) {
                            eprintln!("Couldn't write to file: {}", e);
                        }
                    } else {
                        unreachable!("Possible options only: 1 and 2!");
                    }
                }
                Err(_) => panic!("Master password verification failed!"),
            }
        }
        Err(_) => {
            println!("Enter master password: ");
            std::io::stdin()
                .read_line(&mut password)
                .expect("Failed to read line");
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA512,
                n_iter,
                &salt,
                password.as_bytes(),
                &mut pbkdf2_hash,
            );

            save_master_password(password.as_bytes()).expect("Failed to save master password!");
        }
    }
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

#[test]
fn test_verify_master_password() {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let mut salt = [0u8; CREDENTIAL_LEN];
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt,
        b"password",
        &mut pbkdf2_hash,
    );
    assert!(verify_master_password("password", n_iter, &salt, &mut pbkdf2_hash).is_ok());
}
