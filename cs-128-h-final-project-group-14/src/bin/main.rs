mod tiny_encryp_alg;
mod tiny_decryp_alg;
mod subs_decryp_alg;
mod subs_encryp_alg;
mod elliptic_decryp_alg;
mod elliptic_encryp_alg;

use tiny_encryp_alg::TinyEncrypAlg;
use subs_encryp_alg::SubstitutionEncrypt;
use elliptic_encryp_alg::EllipticEncryptAlg;

use tiny_decryp_alg::TinyDecrypAlg;

use subs_decryp_alg::SubstitutionDecrypt;
use elliptic_decryp_alg::EllipticDecryptAlg;
use elliptic_decryp_alg::Point;
use std::io;
//use std::collections::HashMap;
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

fn parse_point_pairs(input: &str) -> Result<Vec<(Point, Point)>, String> {
    input
        .split('|')
        .map(|pair_str| pair_str.trim())
        .filter(|s| !s.is_empty())
        .map(|pair_str| {
            let mut points = pair_str.split(';');
            
            let p1_str = points.next().ok_or("Missing first point in pair")?;
            let p2_str = points.next().ok_or("Missing second point in pair")?;
            
            if points.next().is_some() {
                return Err("A pair cannot contain more than two points".to_string());
            }
            let p1 = p1_str.parse::<Point>()?;
            let p2 = p2_str.parse::<Point>()?;

            Ok((p1, p2))
        })
        .collect()
}

fn main() {
    let mut keep_looping = true;

    while keep_looping {
        println!("Do you want to encrypt or decrypt? (Enter 'stop' to exit)");
        let mut encrypt_or_decrypt = String::new();
        io::stdin().read_line(&mut encrypt_or_decrypt).expect("Failed to read line");

        match encrypt_or_decrypt.trim() {
            "encrypt" => {
                println!("Enter your message: ");
                let mut message = String::new();
                io::stdin().read_line(&mut message).expect("Failed to read line");

                println!("Enter your enryption choice (Tiny Encryption, Substitution, Elliptic Curve): ");
                let mut encryp_type = String::new();
                io::stdin().read_line(&mut encryp_type).expect("Failed to read line");

            
        
                match encryp_type.trim() {
                    "Tiny Encryption" => { 
                        println!("Enter a string for your key: ");
                        let mut key = String::new();
                        io::stdin().read_line(&mut key).expect("Failed to read line");
                        let mut tiny_encryp_alg = TinyEncrypAlg::new(message, key);
                        tiny_encryp_alg.encrypt();
                        println!("Here is your encrypted message: {}", &tiny_encryp_alg.encrypted);
                    },
                    "Substitution" => {
                        println!("Enter a string for your key: ");
                        let mut key = String::new();
                        io::stdin().read_line(&mut key).expect("Failed to read line");
                        let mut subs_encryp_alg = SubstitutionEncrypt::new(message, key);
                        subs_encryp_alg.encrypt();
                        println!("Here is your encrypted message: {}", &subs_encryp_alg.encrypted);
                    },
                    "Elliptic" => {
                        println!("Enter an x value: ");
                        let mut point_x = String::new(); 
                        io::stdin().read_line(&mut point_x).expect("Failed to read line");
                        println!("Enter an y value: ");
                        let mut point_y = String::new(); 
                        io::stdin().read_line(&mut point_y).expect("Failed to read line");
                        let mut elliptic_encryp_alg = EllipticEncryptAlg::new(message, point_x, point_y);
                        elliptic_encryp_alg.encrypt();
                        println!("Here is your encrypted message: {:?}", &elliptic_encryp_alg.encrypted);
                    },
                    _ => {
                        println!("Invalid encryption method\n");
                    },
                };
            },

            "decrypt" => {
                println!("Enter your encrypted message. \n\n\
                If your choice of decryption is Elliptic curve, format your curve as follows:\n  \
                    • Use '|' to separate each tuple pair.\n  \
                    • Use ';' to separate the first and second Point in a pair.\n  \
                    • Use ',' to separate X and Y coordinates.\n  \
                    • Use 'inf' or 'infinity' to represent a point at infinity.\n\n\
                    Example: 3,6;10,85 | inf;12,34");

                let mut message = String::new();
                io::stdin().read_line(&mut message).expect("Failed to read line");

                println!("Enter your deryption choice (Tiny Encryption, Substitution, Elliptic Curve): ");
                let mut decryp_type = String::new();
                io::stdin().read_line(&mut decryp_type).expect("Failed to read line");

                println!(
                    "Enter a string for your key."
                );
                let mut key = String::new();
                io::stdin().read_line(&mut key).expect("Failed to read line");
        
                match decryp_type.trim() {
                    "Tiny Encryption" => { 
                        let mut tiny_decryp_alg = TinyDecrypAlg::new(message, key);
                        tiny_decryp_alg.decrypt();
                        println!("Here is your encrypted message: {}", &tiny_decryp_alg.decrypted);
                    },
                    "Substitution" => {
                        let mut subs_decryp_alg = SubstitutionDecrypt::new(message, key);
                        subs_decryp_alg.decrypt();
                        println!("Here is your encrypted message: {}", &subs_decryp_alg.decrypted);
                    },
                    "Elliptic" => {
                        let int_key = key.parse::<i64>().expect("Not a number");
                        match parse_point_pairs(&message) {
                            Ok(vector) => {
                                let mut elliptic_decryp_alg = EllipticDecryptAlg::new(vector, int_key);
                                elliptic_decryp_alg.decrypt();
                                println!("Here is your encrypted message: {:?}", &elliptic_decryp_alg.decrypted);
                            }
                            Err(e) => eprintln!("Failed to parse: {}", e),
                        }
                    },
                    _ => {
                        println!("Invalid decryption method\n");
                    },
                };
            },
            "stop" => { keep_looping = false },
            _ => {
                println!("Invalid answer\n");
            },
        };
        println!("\n");
    }

}
