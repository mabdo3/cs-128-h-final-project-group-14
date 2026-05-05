use base64::{engine::general_purpose, Engine as _};

const DELTA: u32 = 0x9e3779b9;
#[derive(Debug, Clone, PartialEq)]

pub struct TinyDecrypAlg {
	pub message: Vec<u32>,
	pub key: [u32; 4],
	pub decrypted: String,
}

impl TinyDecrypAlg {
	pub fn new(message_string: String, key_string: String) -> TinyDecrypAlg {
		let message_clean: String = message_string.chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .collect();
		let message_bytes = general_purpose::STANDARD.decode(message_clean.clone()).expect("Failed to decode base64");
		assert!(message_bytes.len() % 4 == 0,"Decoded data is not aligned to 4 bytes");
		let message: Vec<u32> = message_bytes.chunks(4).map(|b| {u32::from_le_bytes(b.try_into().unwrap())}).collect();
		let key = Self::key_from_str(&key_string);
		println!("Base64 input: {}", message_string.clone());
		println!("Decoded bytes: {}", message_bytes.len());
		println!("Modulo 8: {}", message_bytes.len() % 8);
		TinyDecrypAlg{message, key, decrypted: String::new()}
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

	pub fn decrypt(&mut self) {
		let mut x = self.message.clone();
		for chunk in x.chunks_exact_mut(2) {
			let mut v0 = chunk[0];
			let mut v1 = chunk[1];
			let mut sum = DELTA.wrapping_mul(32);
			for _ in 0..32 {
				v1 = v1.wrapping_sub(
					((v0 << 4).wrapping_add(self.key[2]))
					^ v0.wrapping_add(sum)
					^ ((v0 >> 5).wrapping_add(self.key[3]))
				);

				v0 = v0.wrapping_sub(
					((v1 << 4).wrapping_add(self.key[0]))
					^ v1.wrapping_add(sum)
					^ ((v1 >> 5).wrapping_add(self.key[1]))
				);

				sum = sum.wrapping_sub(DELTA);
			}
			chunk[0] = v0;
			chunk[1] = v1;
		}
		assert!(x.len() % 2 == 0, "Invalid block size");
		let mut bytes = Vec::with_capacity(x.len() * 4);
		for &word in &x {
			bytes.extend_from_slice(&word.to_le_bytes());
		}
		println!("Decrypted raw bytes: {:?}", bytes);
		println!("Decrypted raw bytes:");
		for b in &bytes {
			print!("{:02x} ", b);
		}
		println!();
		let bytes = Self::pad_inverse(bytes);
		self.decrypted = String::from_utf8(bytes).expect("Invalid UTF-8");
	}

	fn pad_inverse(mut data: Vec<u8>) -> Vec<u8> {
		if let Some(&pad_len) = data.last() {
			let pad_len = pad_len as usize;

			if pad_len == 0 || pad_len > 8 || pad_len > data.len() {
				panic!("Invalid padding");
			}

			let start = data.len().checked_sub(pad_len).expect("Invalid padding length");

			if data[start..].iter().any(|&b| b != pad_len as u8) {
				panic!("Invalid padding content");
			}

			data.truncate(data.len() - pad_len);
			data
		} else {
			panic!("Empty data");
		}
	}
}