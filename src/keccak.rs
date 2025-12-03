//! The `Keccak` hash functions.

use super::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState};

/// The `Keccak` hash functions defined in [`Keccak SHA3 submission`].
///
/// # Usage
///
/// ```toml
/// [dependencies]
/// tiny-keccak = { version = "2.0.0", features = ["keccak"] }
/// ```
///
/// [`Keccak SHA3 submission`]: https://keccak.team/files/Keccak-submission-3.pdf
#[derive(Clone)]
pub struct Keccak {
    /// Internal Keccak state.
    pub state: KeccakState<KeccakF>,
}

impl Keccak {
    const DELIM: u8 = 0x01;

    /// Creates  new [`Keccak`] hasher with a security level of 224 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v224() -> Keccak {
        Keccak::new(224)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Keccak {
        Keccak::new(256)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 384 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v384() -> Keccak {
        Keccak::new(384)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 512 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v512() -> Keccak {
        Keccak::new(512)
    }

    fn new(bits: usize) -> Keccak {
        Keccak {
            state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
        }
    }
}

impl Hasher for Keccak {
    /// Absorb additional input. Can be called multiple times.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let mut keccak = Keccak::v256();
    /// keccak.update(b"hello");
    /// keccak.update(b" world");
    /// # }
    /// ```
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Pad and squeeze the state to the output.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let keccak = Keccak::v256();
    /// # let mut output = [0u8; 32];
    /// keccak.finalize(&mut output);
    /// # }
    /// #
    /// ```
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::Keccak;
    use crate::Hasher;

    fn finalize(mut hasher: Keccak, output: &mut [u8]) {
        let words: &mut [u64; 25] = hasher.state.buffer.words();
        let input: &mut [u8; 200] = unsafe { core::mem::transmute(words) };
        let buffer: &mut [u8] = &mut input[0..136];

        for i in hasher.state.offset..hasher.state.rate {
            buffer[i] = 0;
        }
        buffer[hasher.state.offset] |= 0x01;
        buffer[hasher.state.rate - 1] |= 0x80;
        
        hasher.update(buffer);
        hasher.state.buffer.setout(output, hasher.state.offset, output.len());
        std::println!("buffer: {:?}", hasher.state.buffer.words());
    }

    #[test]
    fn test_specs() {
        let mut hasher = Keccak::v256();
        let input: &[u8] = &[1; 136];
        hasher.update(input);

        std::println!("buffer: {:?}", hasher.state.buffer.words());
        std::println!("offset: {:?}", hasher.state.offset);

        let input2: &[u8] = &[1; 1];
        hasher.update(input2);

        std::println!("buffer: {:?}", hasher.state.buffer.words());
        std::println!("offset: {:?}", hasher.state.offset);

        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        std::println!("output: {:?}", output);
        
    }

    #[test]
    fn test_finalize() {
        let mut hasher = Keccak::v256();
        let input: &[u8] = &[1; 136];
        hasher.update(input);

        std::println!("buffer: {:?}", hasher.state.buffer.words());
        std::println!("offset: {:?}", hasher.state.offset);

        let input2: &[u8] = &[1; 1];
        hasher.update(input2);

        std::println!("buffer: {:?}", hasher.state.buffer.words());
        std::println!("offset: {:?}", hasher.state.offset);

        let mut output = [0u8; 32];
        finalize(hasher, &mut output);
        std::println!("{:?}", output);
    }
}
