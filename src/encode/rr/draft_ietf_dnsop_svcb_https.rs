use crate::encode::Encoder;
use crate::EncodeResult;
use crate::rr::{Class, HTTPS, ServiceBindingMode, SVCB, Type};

impl Encoder {
    /// Encode a service binding (SVCB) resource record
    pub(super) fn rr_svcb(&mut self, svcb: &SVCB) -> EncodeResult<()> {
        self.domain_name(&svcb.name)?;
        self.rr_type(&Type::SVCB);
        self.rr_class(&Class::IN);
        self.u32(svcb.ttl);

        // RDATA: RFC section 2.2
        let length_index = self.create_length_index();
        self.u16(svcb.priority);
        self.domain_name(&svcb.target_name)?;
        if svcb.mode() == ServiceBindingMode::Service {
            // TODO ensure sorting
            svcb.parameters.iter().for_each(|parameter| -> () {
                self.u16(parameter.get_registered_number());
                let value = parameter.get_wire_data();
                self.u16(value.len() as u16);
                self.vec(&value);
            });
        }
        self.set_length_index(length_index)
    }

    /// Encode an HTTPS resource record
    pub(super) fn rr_https(&mut self, https: &HTTPS) -> EncodeResult<()> {
        self.domain_name(&https.name)?;
        self.rr_type(&Type::SVCB);
        self.rr_class(&Class::IN);
        self.u32(https.ttl);

        // RDATA: RFC section 2.2
        let length_index = self.create_length_index();
        self.u16(https.priority);
        self.domain_name(&https.target_name)?;
        if https.mode() == ServiceBindingMode::Service {
            // TODO ensure sorting
            https.parameters.iter().for_each(|parameter| -> () {
                self.u16(parameter.get_registered_number());
                let value = parameter.get_wire_data();
                self.u16(value.len() as u16);
                self.vec(&value);
            });
        }
        self.set_length_index(length_index)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::{DomainName, Dns, Flags, RCode, Opcode};
    use crate::encode::encoder::Encoder;
    use crate::rr::{SVCB, RR};
    use crate::question::{Question, QClass, QType};

    // #[test] // FIXME
    fn encode_service_binding() {
        // given
        let mut encoder = Encoder::default();
        let domain_name = DomainName::try_from("_8765._baz.api.test").unwrap();
        let target_name = DomainName::try_from("svc4-baz.test").unwrap();
        let service_binding = SVCB {
            name: domain_name.to_owned(),
            ttl: 7200,
            priority: 0,
            target_name,
            parameters: vec![],
        };
        let dns = Dns {
            id: 0xeced,
            flags: Flags {
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: RCode::NoError
            },
            questions: vec![
                Question {
                    domain_name,
                    q_class: QClass::IN,
                    q_type: QType::SVCB,
                },
            ],
            answers: vec![
                RR::SVCB(service_binding.to_owned()),
            ],
            authorities: vec![],
            additionals: vec![]
        };

        // when
        let wire_data = encoder.dns(&dns);

        // then
        wire_data.expect(format!("Unable to encode: {}", service_binding).as_str());

        assert_eq!(hex::encode(encoder.bytes),
                   hex::encode(&b"\xec\xed\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05_8765\x04_baz\x03api\x04test\x00\x00\x40\x00\x01\xc0\x0c\x00\x40\x00\x01\x1c\x20\x00\x12\x00\x00\x08svc4-baz\x04test"[..]));
    }
}