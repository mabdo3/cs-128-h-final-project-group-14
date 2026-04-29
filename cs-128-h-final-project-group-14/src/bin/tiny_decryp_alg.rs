const DELTA: u32 = 0x9e3779b9;
#[derive(Debug, Clone, PartialEq)]

pub struct TinyDecrypAlg {
	pub message: Vec<u32>,
	pub key: Vec<u32>,
	pub decrypted: String,
}

impl TinyDecrypAlg {
	pub fn new(message_string: String, key_string: String) -> TinyDecrypAlg {
		let message = message_string.clone().into_bytes().into_iter().map(|b| b as u32).collect();
		let key = key_string.clone().into_bytes().into_iter().map(|b| b as u32).collect();
		TinyDecrypAlg{message, key, decrypted: String::new()}
	}

	pub fn decrypt(&mut self) {
		let mut x = self.message.clone();
		for chunk in x.chunks_mut(2) {
			let mut v0 = chunk[0];
			let mut v1 = chunk[1];
			let mut sum = DELTA << 5;
			for _j in 0..32 {
				v1 -= ((v0 << 4) + self.key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + self.key[3]);
				v0 -= ((v1 << 4) + self.key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + self.key[1]);
				sum -= DELTA;
			}
		}
		self.decrypted = match String::from_utf8(x.into_iter().map(|b| b as u8).collect()) {
			Ok(y) => y,
			Err(_from_utf_8_error) => String::new(),
		};
	}
}