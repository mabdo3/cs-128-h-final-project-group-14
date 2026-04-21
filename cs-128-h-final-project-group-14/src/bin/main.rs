mod tiny_encryp_alg;
mod tiny_decryp_alg;
mod subs_decryp_alg;
mod subs_encryp_alg;
mod elliptic_decryp_alg;
mod elliptic_encryp_alg;

use tiny_encryp_alg::TinyEncrypAlg;
use subs_encryp_alg::SubstitutionEncrypt;
use elliptic_encryp_alg::EllipticCurveAlg;
use std::io;
use std::collections::HashMap;
use core::result::Result;

fn main() {
    let mut tiny_keys: Vec<TinyEncrypAlg> = Vec::new();
    let mut subs_keys: Vec<SubstitutionEncrypt> = Vec::new();
    let mut elliptic_keys: Vec<EllipticCurveAlg> = Vec::new();


    println!("Do you want to encrypt or decrpt?");
    let mut encrypt_or_decrypt = String::new();
    io::stdin().read_line(&mut encrypt_or_decrypt).expect("Failed to read line");

    let encrypt = String::from("encrypt");
    let decrypt = String::from("decrypt");
    match encrypt_or_decrypt {
        encrypt => {
            println!("Enter your message: ");
            let mut message = String::new();
            io::stdin().read_line(&mut message).expect("Failed to read line");

            println!("Enter your enryption choice (Tiny Encryption, Substitution, Elliptic Curve): ");
            let mut encryp_type = String::new();
            io::stdin().read_line(&mut encryp_type).expect("Failed to read line");

            println!("Enter a string for your key: ");
            let mut key = String::new();
            io::stdin().read_line(&mut key).expect("Failed to read line");
    
            let tiny = String::from("Tiny Encryption");
            let subs = String::from("Substitution");
            let elliptic = String::from("Elliptic");
            match encryp_type {
                 tiny => { 
                    let mut tiny_encryp_alg = TinyEncrypAlg::new(message, key);
                    tiny_encryp_alg.encrypt();
                    println!("Here is your encrypted message: {}", &tiny_encryp_alg.encrypted);
                    tiny_keys.push(tiny_encryp_alg);
                  },
                 subs => {
                     let mut subs_encryp_alg = SubstitutionEncrypt::new(message, key);
                     subs_encryp_alg.encrypt();
                     println!("Here is your encrypted message: {}", &subs_encryp_alg.encrypted);
                     subs_keys.push(subs_encryp_alg);
                 },
                 elliptic => {
                     let int_key = key.parse::<i64>().expect("Not a number");
                     let mut elliptic_encryp_alg = EllipticCurveAlg::new(message, int_key);
                     elliptic_encryp_alg.encrypt();
                     println!("Here is your encrypted message: {:?}", &elliptic_encryp_alg.encrypted);
                     elliptic_keys.push(elliptic_encryp_alg);
                 },
            };
        },

        decrypt => {
            println!("Enter your message: ");
            let mut message = String::new();
            io::stdin().read_line(&mut message).expect("Failed to read line");

            println!("Enter your deryption choice (Tiny Encryption, Substitution, Elliptic Curve): ");
            let mut decryp_type = String::new();
            io::stdin().read_line(&mut decryp_type).expect("Failed to read line");
    
            let tiny = String::from("Tiny Encryption");
            let subs = String::from("Substitution");
            let elliptic = String::from("Elliptic");
            match decryp_type {
                 tiny => { 
                    println!("Enter a string for your key: ");
                    let mut key = String::new();
                    io::stdin().read_line(&mut key).expect("Failed to read line");
                 },
                 subs => {
                     println!("Enter a string for your key: ");
                 },
                 elliptic => {
                     println!("Enter a number for your key: ");
                 },
            };
        },
    };

}
