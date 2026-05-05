mod tiny_encryp_alg;
mod tiny_decryp_alg;
mod subs_decryp_alg;
mod subs_encryp_alg;
mod elliptic_alg; // Consolidated file
mod point; 

use tiny_encryp_alg::TinyEncrypAlg;
use subs_encryp_alg::SubstitutionEncrypt;
use elliptic_alg::EllipticEncryptAlg; // Updated import

use tiny_decryp_alg::TinyDecrypAlg;
use subs_decryp_alg::SubstitutionDecrypt;

use std::io;
use point::Point;
use core::result::Result;
use std::str::FromStr;

impl FromStr for Point {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("inf") || s.eq_ignore_ascii_case("infinity") {
            return Ok(Point::infinity());
        }
        let mut parts = s.split(',');
        let x_str = parts.next().ok_or("Missing X coordinate")?.trim();
        let y_str = parts.next().ok_or("Missing Y coordinate")?.trim();
        let x = x_str.parse::<i64>().map_err(|_| format!("Invalid X: {x_str}"))?;
        let y = y_str.parse::<i64>().map_err(|_| format!("Invalid Y: {y_str}"))?;
        Ok(Point { x, y, infinity: false })
    }
}

fn main() {
    let mut keep_looping = true;

    while keep_looping {
        println!();
        println!("Do you want to encrypt or decrypt? (Enter 'stop' to exit)");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed");

        match choice.trim() {
            "encrypt" => {
                println!();
                println!("Enter your message: ");
                let mut message = String::new();
                io::stdin().read_line(&mut message).expect("Failed");

                println!();
                println!("Enter choice (Tiny Encryption, Substitution, Elliptic): ");
                let mut enc_type = String::new();
                io::stdin().read_line(&mut enc_type).expect("Failed");

                match enc_type.trim() {
                    "Tiny Encryption" => {
                        println!();
                        println!("Enter a string for your key: ");
                        let mut key = String::new(); 
                        io::stdin().read_line(&mut key).expect("Failed");
                        let mut alg = TinyEncrypAlg::new(message, key); // example
                        alg.encrypt();
                        println!();
                        println!("Encrypted: {}", alg.encrypted);
                    },
                    "Substitution" => {
                        println!();
                        println!("Enter a string for your key: ");
                        let mut key = String::new(); 
                        io::stdin().read_line(&mut key).expect("Failed");
                        let mut alg = SubstitutionEncrypt::new(message, key);
                        alg.encrypt();
                        println!();
                        println!("Encrypted: {}", alg.encrypted);
                    },
                    "Elliptic" => {
                        println!();
                        println!("Enter an int key: ");
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).expect("Failed"); 
                        let key = input.trim().parse::<i64>().unwrap_or(0);
                        let mut alg = EllipticEncryptAlg::new(message.trim().to_string(), key);
                        alg.encrypt();
                        println!();
                        println!("Here is your encrypted message: {}", alg.encrypted);
                    },
                    _ => println!("Invalid choice"),
                }
            },

            "decrypt" => {
                println!();
                println!("Enter your encrypted message (e.g., 3,6;10,85 | 12,34;55,21 for Elliptic): ");
                let mut message = String::new();
                io::stdin().read_line(&mut message).expect("Failed");

                println!();
                println!("Enter choice (Tiny Encryption, Substitution, Elliptic): ");
                let mut dec_type = String::new();
                io::stdin().read_line(&mut dec_type).expect("Failed");

                println!();
                println!("Enter your key: ");
                let mut key_str = String::new();
                io::stdin().read_line(&mut key_str).expect("Failed");
        
                match dec_type.trim() {
                    "Tiny Encryption" => { 
                        let mut alg = TinyDecrypAlg::new(message, key_str.into());
                        alg.decrypt();
                        println!();
                        println!("Decrypted: {}", alg.decrypted);
                    },
                    "Substitution" => {
                        let mut alg = SubstitutionDecrypt::new(message, key_str.trim().into());
                        alg.decrypt();
                        println!();
                        println!("Decrypted: {}", alg.decrypted);
                    },
                    "Elliptic" => {
                        let key_str = key_str.trim().parse::<i64>().expect("Not a number");
                        let mut alg = EllipticEncryptAlg::new(String::new(), key_str);
                        alg.encrypted = message.trim().to_string();
                        let decrypted = alg.decrypt();
                        println!();
                        println!("Here is your decrypted message: {}", decrypted);
                    },
                    _ => println!("Invalid choice"),
                };
            },
            "stop" => keep_looping = false,
            _ => println!("Invalid answer"),
        }
    }
}