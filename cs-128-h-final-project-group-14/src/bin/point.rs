#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point {
    pub x: i64,
    pub y: i64,
    pub infinity: bool,
}

impl Point {
    pub fn infinity() -> Self {
        Point {
            x: 0,
            y: 0,
            infinity: true,
        }
    }
}