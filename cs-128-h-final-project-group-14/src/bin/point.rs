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
        let x = ex.trim().parse::<i64>().expect("Not a number"); 
        let y = why.trim().parse::<i64>().expect("Not a number"); 
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