use base64::{engine::general_purpose, Engine as _};

const DELTA: u32 = 0x9e3779b9;
#[derive(Debug, Clone, PartialEq)]

pub struct TinyEncrypAlg {
	pub message: Vec<u32>,
	pub key: [u32; 4],
	pub encrypted: String,
}

impl TinyEncrypAlg {
	pub fn new(message_string: String, key_string: String) -> TinyEncrypAlg {
		let padded = Self::pad(message_string.into_bytes());

		assert!(
			padded.len() % 4 == 0,
			"Padding error: not multiple of 4 bytes"
		);

		let message = padded
			.chunks_exact(4)
			.map(|b| u32::from_le_bytes(b.try_into().unwrap()))
			.collect::<Vec<u32>>();
		let key = Self::key_from_str(&key_string);
		TinyEncrypAlg{message, key, encrypted: String::new()}	
	}

	pub fn key_from_str(s: &str) -> [u32; 4] {
		let mut b = [0u8; 16];
		let bytes = s.as_bytes();
		let len = bytes.len().min(16);
		b[..len].copy_from_slice(&bytes[..len]);

		[
			u32::from_le_bytes(b[0..4].try_into().unwrap()),
			u32::from_le_bytes(b[4..8].try_into().unwrap()),
			u32::from_le_bytes(b[8..12].try_into().unwrap()),
			u32::from_le_bytes(b[12..16].try_into().unwrap()),
		]
	}

	pub fn pad(data: Vec<u8>) -> Vec<u8> {
		let pad_len = 8 - (data.len() % 8);
		let pad_len = if pad_len == 0 { 8 } else { pad_len };

		let mut data = data;
		data.extend(std::iter::repeat(pad_len as u8).take(pad_len));
		data
	}

	pub fn encrypt(&mut self) {
		let mut x = self.message.clone();
		for chunk in x.chunks_exact_mut(2) {
			let mut v0 = chunk[0];
			let mut v1 = chunk[1];
			let mut sum: u32 = 0;
			for _ in 0..32 {
				sum = sum.wrapping_add(DELTA);
				v0 = v0.wrapping_add(((v1 << 4).wrapping_add(self.key[0])) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(self.key[1])));
				v1 = v1.wrapping_add(((v0 << 4).wrapping_add(self.key[2])) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(self.key[3])));
			}
			chunk[0] = v0;
			chunk[1] = v1;
		}
		let mut bytes = Vec::with_capacity(x.len() * 4);
		for &word in &x {
			bytes.extend_from_slice(&word.to_le_bytes());
		}
		self.encrypted = general_purpose::STANDARD.encode(&bytes);
	}
}