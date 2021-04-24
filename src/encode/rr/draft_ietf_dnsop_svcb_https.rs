use crate::{EncodeError, EncodeResult};
use crate::encode::Encoder;
use crate::rr::{Class, ServiceBinding, ServiceBindingMode, ServiceParameter, Type};

impl Encoder {
    /// Encode a service binding (SVCB or HTTPS) resource record
    pub(super) fn rr_service_binding(&mut self, service_binding: &ServiceBinding) -> EncodeResult<()> {
        let rr_type = if service_binding.https { &Type::HTTPS } else { &Type::SVCB };
        self.domain_name(&service_binding.name)?;
        self.rr_type(rr_type);
        self.rr_class(&Class::IN);
        self.u32(service_binding.ttl);

        // RDATA wire format: RFC section 2.2
        let length_index = self.create_length_index();
        self.u16(service_binding.priority);
        self.domain_name(&service_binding.target_name)?;
        if service_binding.mode() == ServiceBindingMode::Service {
            let mut parameters = service_binding.parameters.clone();
            parameters.sort();
            for parameter in parameters {
                self.rr_service_parameter(&parameter)?;
            }
        }
        self.set_length_index(length_index)
    }

    fn rr_service_parameter(&mut self, parameter: &ServiceParameter) -> EncodeResult<()> {
        self.u16(parameter.get_registered_number());
        let length_index = self.create_length_index();
        match parameter {
            ServiceParameter::MANDATORY { key_ids } => {
                for key_id in key_ids {
                    self.u16(*key_id);
                }
            }
            ServiceParameter::ALPN { alpn_ids } => {
                for alpn_id in alpn_ids {
                    self.string(alpn_id)?;
                }
            }
            ServiceParameter::NO_DEFAULT_ALPN => {}
            ServiceParameter::PORT { port } => {
                self.u16(*port);
            }
            ServiceParameter::IPV4_HINT { hints } => {
                for hint in hints {
                    self.ipv4_addr(hint);
                }
            }
            ServiceParameter::ECH_CONFIG { config_list } => {
                if config_list.len() > u16::MAX as usize {
                    return Err(EncodeError::Length(config_list.len()));
                }
                self.u16(config_list.len() as u16);
                self.vec(config_list);
            }
            ServiceParameter::IPV6_HINT { hints } => {
                for hint in hints {
                    self.ipv6_addr(hint);
                }
            }
            ServiceParameter::PRIVATE { number: _, presentation_key: _, wire_data, presentation_value: _ } => {
                self.vec(wire_data);
            }
            ServiceParameter::KEY_65535 => {}
        }
        self.set_length_index(length_index)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::{Dns, DomainName, EncodeError, Flags, Opcode, RCode};
    use crate::domain_name::DomainNameError::DomainNameLength;
    use crate::encode::encoder::Encoder;
    use crate::question::{QClass, QType, Question};
    use crate::question::QType::{HTTPS, SVCB};
    use crate::rr::{RR, ServiceBinding, ServiceBindingMode};

    #[test]
    fn encode_decode_service_binding() {
        // given
        let mut encoder = Encoder::default();
        let domain_name = DomainName::try_from("_8765._baz.api.test").unwrap();
        let target_name = DomainName::try_from("svc4-baz.test").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name.to_owned(),
            ttl: 7200,
            priority: 0,
            target_name,
            parameters: vec![],
            https: false,
        };
        let dns = dns(0xeced, service_binding, false);

        // when
        encoder.dns(&dns).unwrap();

        // then
        let result = Dns::decode(encoder.bytes.freeze()).expect("Unable to parse encoded DNS");
        assert_eq!(result.answers.len(), 1);
        let answer = &result.answers[0];
        assert!(matches!(answer, RR::SVCB(service_binding) if service_binding.mode() == ServiceBindingMode::Alias))
    }

    #[test]
    fn alias_form() {
        // given
        let mut encoder = Encoder::default();
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name.to_owned(),
            ttl: 300,
            priority: 0,
            target_name,
            parameters: vec![],
            https: false,
        };
        let dns = dns(0xdece, service_binding.to_owned(), false);

        // when
        let result = encoder.dns(&dns).unwrap();

        // then
        let mut expected = vec![];
        expected.extend_from_slice(b"\x00\x00"); // priority
        expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
        expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)

        let (prefix, suffix) = encoder.bytes
            .split_at(encoder.bytes.len() - expected.len());
        assert_eq!(suffix, expected.as_slice());
    }

    fn response_flag() -> Flags {
        Flags {
            qr: true,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            ad: false,
            cd: false,
            rcode: RCode::NoError,
        }
    }

    fn dns(id: u16, service_binding: ServiceBinding, https: bool) -> Dns {
        Dns {
            id,
            flags: response_flag(),
            questions: vec![
                Question {
                    domain_name: service_binding.name.to_owned(),
                    q_class: QClass::IN,
                    q_type: if https { HTTPS } else { SVCB },
                }
            ],
            answers: vec![
                if https { RR::HTTPS(service_binding) } else { RR::SVCB(service_binding) }
            ],
            authorities: vec![],
            additionals: vec![],
        }
    }
}