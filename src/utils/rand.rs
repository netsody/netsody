use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng());
}

pub fn pseudorandom_bytes(buf: &mut [u8]) {
    RNG.with(|rng| {
        rng.borrow_mut().fill_bytes(buf);
    });
}
