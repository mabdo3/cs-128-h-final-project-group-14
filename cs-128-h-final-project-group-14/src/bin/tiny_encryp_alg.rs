const DELTA: u32 = 0x9e3779b9;


#[derive(Debug, Clone, PartialEq)]
pub struct TinyEncrypAlg {
	pub message: Vec<u32>,
	pub key: Vec<u32>,
	pub encrypted: String,
}

impl TinyEncrypAlg {
	pub fn new(message_string: String, key_string: String) -> TinyEncrypAlg {
		let message = message_string.clone().into_bytes().into_iter().map(|b| b as u32).collect();
		let key = key_string.clone().into_bytes().into_iter().map(|b| b as u32).collect();
		TinyEncrypAlg{message, key, encrypted: String::new()}	
	}

	pub fn encrypt(&mut self) {
		let mut x = self.message.clone();
		for chunk in x.chunks_mut(2) {
			let mut v0 = chunk[0];
			let mut v1 = chunk[1];
			let mut sum = 0;
			for _j in 0..32 {
				sum += DELTA;
				v0 += ((v1 << 4) + self.key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + self.key[1]);
				v1 += ((v0 << 4) + self.key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + self.key[3]);
			}

		}
		self.encrypted = match String::from_utf8(x.into_iter().map(|b| b as u8).collect()) {
			Ok(y) => y,
			Err(_FromUtf8Error) => String::new(),
		};
	}
}