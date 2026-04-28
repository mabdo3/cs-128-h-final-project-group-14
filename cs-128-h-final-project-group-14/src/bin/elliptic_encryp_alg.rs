use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point {
    pub x: i64,
    pub y: i64,
    pub infinity: bool,
}

impl Point {
    pub fn new(ex: String, why: String) -> Self {
        if ex == "infinity" || why == "infinity" {
            return Self::infinity(); 
        } 
        let x = ex.parse::<i64>().expect("Not a number"); 
        let y = why.parse::<i64>().expect("Not a number"); 
        return Self{x: x, y: y, infinity: false}; 
    }
    pub fn infinity() -> Self {
        Point {
            x: 0,
            y: 0,
            infinity: true,
        }
    }
}

const A: i64 = 2;
const P: i64 = 97;

const GENERATOR: Point = Point {
    x: 3,
    y: 6,
    infinity: false,
};

#[derive(Debug)]
pub struct EllipticEncryptAlg {
    pub public_key_one: String,
    pub public_key_two: String, 
    pub plaintext: String,
    pub encrypted: Vec<(Point, Point)>,
    lookup: HashMap<u8, Point>,
}

impl EllipticEncryptAlg {


    pub fn new(plaintext: String, public_key_one: String, public_key_two: String) -> Self {
        Self {
            plaintext,
            public_key_one,
            public_key_two,
            encrypted: Vec::new(),
            lookup: Self::build_lookup(),
        }
    }

    fn build_lookup() -> HashMap<u8, Point> {
        let mut map = HashMap::new();

        for i in 0..=255 {
            let p = Self::scalar_mult(i as i64, GENERATOR);
            map.insert(i, p);
        }

        map
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

    fn random_k() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();

        (nanos as i64 % (P - 1)) + 1
    }


    pub fn encrypt(&mut self) {
        self.encrypted.clear();
        for byte in self.plaintext.bytes() {
            let m_point = self.lookup[&byte];
            let k = Self::random_k();
            let c1 = Self::scalar_mult(k, GENERATOR);
            let p = Point::new(self.public_key_one.clone(), self.public_key_two.clone()); 
            let shared = Self::scalar_mult(k, p);
            let c2 = Self::point_add(m_point, shared);
            self.encrypted.push((c1, c2));
        }
    }
}