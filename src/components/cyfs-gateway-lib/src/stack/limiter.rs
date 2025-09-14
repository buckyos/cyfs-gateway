use sfo_io::Limit;

pub struct Limiter {
    read_limit: Option<usize>,
    write_limit: Option<usize>,
}

impl Limiter {
    pub fn new(read_limit: Option<usize>, write_limit: Option<usize>) -> Self {
        Self {
            read_limit,
            write_limit,
        }
    }
}

impl Limit for Limiter {
    fn read_limit(&self) -> Option<usize> {
        self.read_limit.clone()
    }

    fn write_limit(&self) -> Option<usize> {
        self.write_limit.clone()
    }
}
