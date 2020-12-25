use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum EncodeError {
    #[error("String too big to be encoded as u8: {0}")]
    String(usize),
    #[error("Length too big to be encoded as u16: {0}")]
    Length(usize),
    #[error("Not enough bytes to set the data at the index: got {0} index {1}")]
    NotEnoughBytes(usize, usize),
    #[error("Could not compressed domain name, because offset is too large: {0}")]
    Compression(u16),
    #[error("Could not compressed domain name, because many recursions: {0}")]
    MaxRecursion(usize),
}
