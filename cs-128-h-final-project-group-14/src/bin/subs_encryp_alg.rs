use std::collections::HashMap;
#[derive(Debug, Clone, PartialEq)]

pub struct SubstitutionEncrypt {
    pub message: String,
	pub key_map: HashMap<char, char>,
	pub encrypted: String,
}

impl SubstitutionEncrypt {
    pub fn new(message_string: String, key_string: String) -> Self {
        let mut map = HashMap::new();
        let alphabet = "abcdefghijklmnopqrstuvwxyz";
        let key = key_string.to_lowercase();
        for (a,b) in alphabet.chars().zip(key.chars()) {
            map.insert(a, b);
            map.insert(a.to_ascii_uppercase(), b.to_ascii_uppercase());
        }
        SubstitutionEncrypt {
            message: message_string,
            key_map: map,
            encrypted: String::new(),
        }
    }
    pub fn encrypt(&mut self) {
        let mut result = String::new();

        for c in self.message.chars() {
            match self.key_map.get(&c) {
                Some(&replacement) => result.push(replacement),
                None => result.push(c),
            }
        }

        self.encrypted = result;
    }
}
