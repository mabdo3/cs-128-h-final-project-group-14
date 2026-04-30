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
		let message_bytes = general_purpose::STANDARD.decode(message_string.trim()).expect("Failed to decode base64");
		let message: Vec<u32> = message_bytes.chunks_exact(4).map(|b| {(b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)}).collect();
		let key = Self::key_from_str(&key_string);
		TinyDecrypAlg{message, key, decrypted: String::new()}
	}

	pub fn key_from_str(s: &str) -> [u32; 4] {
        let mut b = [0u8; 16];
        let s = s.as_bytes();
        let len = s.len().min(16);
        b[..len].copy_from_slice(&s[..len]);
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
				v1 = v1.wrapping_sub(((v0 << 4).wrapping_add(self.key[2])) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(self.key[3])));
				v0 = v0.wrapping_sub(((v1 << 4).wrapping_add(self.key[0])) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(self.key[1])));
				sum = sum.wrapping_sub(DELTA);
			}
			chunk[0] = v0;
			chunk[1] = v1;
		}
		let bytes: Vec<u8> = Self::pad_inverse(bytemuck::cast_slice(&x).to_vec()); 
		self.decrypted = String::from_utf8_lossy(&bytes).to_string();
	}

	fn pad_inverse(data: Vec<u8>) -> Vec<u8> {
        let pad_len = *data.last().unwrap() as usize;
        let mut d = data;
        d.truncate(d.len() - pad_len);
        d
    }
}