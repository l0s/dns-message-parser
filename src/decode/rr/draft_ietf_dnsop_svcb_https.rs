use std::convert::TryFrom;

use crate::decode::Decoder;
use crate::{DecodeResult, DecodeError};
use crate::rr::{HTTPS, SVCB};

use super::Header;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_svcb(&mut self, header: Header) -> DecodeResult<SVCB> {
        todo!()
    }

    pub(super) fn rr_https(&mut self, header: Header) -> DecodeResult<HTTPS> {
        todo!()
    }
}

#[cfg(test)]
mod tests{
    use crate::decode::decoder::Decoder;

    #[test]
    fn test() {
        // given
        // let decoder = Decoder::
        // when
        // then
    }

}