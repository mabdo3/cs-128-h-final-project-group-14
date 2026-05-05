use std::collections::HashMap;
use crate::point::Point;

const A: i64 = 2;
const P: i64 = 97;
const ALPHABET_START: u8 = 32;
const ALPHABET_SIZE: u8 = 64;

const GENERATOR: Point = Point {
    x: 3,
    y: 6,
    infinity: false,
};

#[derive(Debug, Clone, PartialEq)]
pub struct EllipticDecryptAlg {
    pub private_key: i64,
    pub encrypted: String,
    pub decrypted: String,
    reverse_lookup: HashMap<Point, u8>,
}

impl EllipticDecryptAlg {



   pub fn new(encrypted: String, private_key: i64) -> Self {
        let (_, reverse_lookup) = Self::build_lookups();
        Self {
            encrypted,
            private_key,
            decrypted: String::new(),
            reverse_lookup,
        }
    }


     fn build_lookups() -> (HashMap<u8, Point>, HashMap<Point, u8>) {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        for i in 0..ALPHABET_SIZE {
            let p = Self::scalar_mult((i as i64) + 1, GENERATOR);
            forward.insert(i, p);
            reverse.insert(p, i);
        }

        (forward, reverse)
    }

    fn mod_inv(x: i64) -> i64 {
        let x = (x % P + P) % P;

        for i in 1..P {
            if (x * i) % P == 1 {
                return i;
            }
        }
        0
    }

    fn point_add(p1: Point, p2: Point) -> Point {

        if p1.infinity { return p2; }
        if p2.infinity { return p1; }

        if p1.x == p2.x && (p1.y + p2.y) % P == 0 {
            return Point::infinity();
        }

        let lambda = if p1 == p2 {
            let num = (3 * p1.x * p1.x + A) % P;
            let den = Self::mod_inv((2 * p1.y) % P);
            (num * den) % P
        } else {
            let num = (p2.y - p1.y) % P;
            let den = Self::mod_inv((p2.x - p1.x) % P);
            (num * den) % P
        };

        let x3 = (lambda * lambda - p1.x - p2.x) % P;
        let y3 = (lambda * (p1.x - x3) - p1.y) % P;

        Point {
            x: (x3 + P) % P,
            y: (y3 + P) % P,
            infinity: false,
        }
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

    fn parse_point(s: &str) ->  Result<Point, String> {
        let s = s.trim();
        if s == "inf" {
            return Ok(Point::infinity());
        }
        let mut parts = s.split(',');

        let x_str = parts.next().ok_or("Missing x")?.trim();
        let y_str = parts.next().ok_or("Missing y")?.trim();

        let x = x_str.parse::<i64>().map_err(|_| format!("Invalid x value: {}", x_str))?;

        let y = y_str.parse::<i64>().map_err(|_| format!("Invalid y value: {}", y_str))?;

        Ok(Point { x, y, infinity: false })
    }

     pub fn decrypt(&mut self)
        -> Result<(), Box<dyn std::error::Error>> {

        let mut output = Vec::new();

        for pair in self.encrypted.split('|') {

            if pair.trim().is_empty() {
                continue;
            }

            let mut parts = pair.split(':');

            let c1_str = parts.next().ok_or("Missing c1")?;
            let c2_str = parts.next().ok_or("Missing c2")?;

            let c1 = Self::parse_point(c1_str)?;
            let c2 = Self::parse_point(c2_str)?;

            let shared = Self::scalar_mult(self.private_key, c1);
        let inverse_shared = Point {
                x: shared.x,
                y: (P - shared.y) % P,
                infinity: shared.infinity,
            };

            let m_point = Self::point_add(c2, inverse_shared);

            if let Some(byte) = self.reverse_lookup.get(&m_point) {
                output.push(byte + ALPHABET_START);
            }
        }

        self.decrypted =
            String::from_utf8_lossy(&output).to_string();

        Ok(())
    }
}