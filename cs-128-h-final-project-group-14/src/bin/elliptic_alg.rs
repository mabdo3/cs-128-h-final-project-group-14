use std::collections::HashMap;
use crate::point::Point;
use std::str::FromStr;

const A: i64 = 2;
const P: i64 = 127; // Increased to handle full alphabet without collisions
const ALPHABET_START: u8 = 32; 
const ALPHABET_SIZE: u8 = 95; 

// A valid generator for P=127, A=2, B=3 is (5, 12)
const GENERATOR: Point = Point { x: 5, y: 12, infinity: false };

#[derive(Debug)]
pub struct EllipticEncryptAlg {
    pub private_key: i64, 
    pub plaintext: String,
    pub encrypted: String,
    lookup: HashMap<u8, Point>,
    reverse_lookup: HashMap<Point, u8>,
}

impl EllipticEncryptAlg {
    pub fn new(plaintext: String, private_key: i64) -> Self {
        let (lookup, reverse_lookup) = Self::build_lookups();
        Self {
            plaintext,
            private_key,
            encrypted: String::new(),
            lookup,
            reverse_lookup,
        }
    }

    fn build_lookups() -> (HashMap<u8, Point>, HashMap<Point, u8>) {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();
        for i in 0..ALPHABET_SIZE {
            // Scalar must be > 0 and < Group Order. 
            let p = Self::scalar_mult((i as i64) + 1, GENERATOR);
            forward.insert(i, p);
            reverse.insert(p, i);
        }
        (forward, reverse)
    }

    fn mod_inv(n: i64) -> i64 {
        let n = n.rem_euclid(P);
        for i in 1..P {
            if (n * i).rem_euclid(P) == 1 { return i; }
        }
        0
    }

    fn point_add(p1: Point, p2: Point) -> Point {
        if p1.infinity { return p2; }
        if p2.infinity { return p1; }
        
        if p1.x == p2.x && (p1.y + p2.y).rem_euclid(P) == 0 {
            return Point::infinity();
        }

        let lambda = if p1.x == p2.x && p1.y == p2.y {
            let num = (3 * p1.x * p1.x + A).rem_euclid(P);
            let den = Self::mod_inv(2 * p1.y);
            (num * den).rem_euclid(P)
        } else {
            let num = (p2.y - p1.y).rem_euclid(P);
            let den = Self::mod_inv(p2.x - p1.x);
            (num * den).rem_euclid(P)
        };

        let x3 = (lambda * lambda - p1.x - p2.x).rem_euclid(P);
        let y3 = (lambda * (p1.x - x3) - p1.y).rem_euclid(P);

        Point { x: x3, y: y3, infinity: false }
    }

    fn scalar_mult(mut k: i64, mut point: Point) -> Point {
        let mut result = Point::infinity();
        while k > 0 {
            if k % 2 == 1 {
                result = Self::point_add(result, point);
            }
            point = Self::point_add(point, point);
            k /= 2;
        }
        result
    }

    pub fn encrypt(&mut self) {
        self.encrypted.clear();
        let mut parts = Vec::new();
        let public_key = Self::scalar_mult(self.private_key, GENERATOR);
        
        for ch in self.plaintext.chars() {
            let byte = ch as u8;
            if byte < ALPHABET_START || byte >= ALPHABET_START + ALPHABET_SIZE {
                continue; 
            }
            let idx = byte - ALPHABET_START;
            let m_point = self.lookup[&idx];
            
            let k = 7; // Static k for testing; can be random_k()
            let c1 = Self::scalar_mult(k, GENERATOR);
            let shared = Self::scalar_mult(k, public_key);
            let c2 = Self::point_add(m_point, shared);

            parts.push(format!("{};{}", Self::point_to_string(c1), Self::point_to_string(c2)));
        }
        self.encrypted = parts.join(" | ");
    }

    pub fn decrypt(&self) -> String {
        let mut decoded = String::new();
        for part in self.encrypted.split('|') {
            let part = part.trim();
            if part.is_empty() { continue; }
            let points: Vec<&str> = part.split(';').collect();
            if points.len() != 2 { continue; }

            let c1 = Point::from_str(points[0].trim()).unwrap_or(Point::infinity());
            let c2 = Point::from_str(points[1].trim()).unwrap_or(Point::infinity());

            let shared = Self::scalar_mult(self.private_key, c1);
            let shared_neg = Point { 
                x: shared.x, 
                y: (P - shared.y).rem_euclid(P), 
                infinity: shared.infinity 
            };
            
            let m_point = Self::point_add(c2, shared_neg);

            if let Some(&idx) = self.reverse_lookup.get(&m_point) {
                decoded.push((idx + ALPHABET_START) as char);
            } else {
                decoded.push('?'); // Failure fallback
            }
        }
        decoded
    }

    fn point_to_string(p: Point) -> String {
        if p.infinity { "inf".to_string() } else { format!("{},{}", p.x, p.y) }
    }
}