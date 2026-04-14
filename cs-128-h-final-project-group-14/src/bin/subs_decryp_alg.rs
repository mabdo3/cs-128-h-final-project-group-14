use std::collections::HashMap;

pub struct SubstitutionDecrypt {
    pub ciphertext: String,
    pub reverse_map: HashMap<char, char>,
    pub decrypted: String,
}

impl SubstitutionDecrypt {
    pub fn new(cipher_text: String, key_string: String) -> Self {
        let mut map = HashMap::new();
        let alphabet = "abcdefghijklmnopqrstuvwxyz";
        let key = key_string.to_lowercase();

        for (a, b) in alphabet.chars().zip(key.chars()) {
            map.insert(b, a);
            map.insert(b.to_ascii_uppercase(), a.to_ascii_uppercase());
        }

        SubstitutionDecrypt {
            ciphertext: cipher_text,
            reverse_map: map,
            decrypted: String::new(),
        }
    }

    pub fn decrypt(&mut self) {
        let mut result = String::new();

        for c in self.ciphertext.chars() {
            match self.reverse_map.get(&c) {
                Some(&original) => result.push(original),
                None => result.push(c),
            }
        }

        self.decrypted = result;
    }
}
