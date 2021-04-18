use crate::encode::Encoder;
use crate::EncodeResult;
use crate::rr::{HTTPS, SVCB};

impl Encoder {
    pub(super) fn rr_svcb(&mut self, svcb: &SVCB) -> EncodeResult<()> {
        self.domain_name(&svcb.name)
    }

    pub(super) fn rr_https(&mut self, https: &HTTPS) -> EncodeResult<()> {
        self.domain_name(&https.name)
    }
}