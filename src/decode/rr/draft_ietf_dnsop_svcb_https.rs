use crate::decode::Decoder;
use crate::decode::error::DecodeError::TooManyBytes;
use crate::DecodeResult;
use crate::rr::{HTTPS, ServiceParameter, SVCB};

use super::Header;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_svcb(&mut self, header: Header) -> DecodeResult<SVCB> {
        let priority = self.u16()?;
        eprintln!("priority: {}", priority);
        let target_name = self.domain_name()?;
        eprintln!("target_name: {}", target_name);
        let mut parameters = vec![];
        if priority != 0 {
            while !self.is_finished()? {
                let service_parameter_key = self.u16()?;
                eprintln!("service_parameter_key: {}", service_parameter_key);
                let value_length = self.u16()?;
                eprintln!("value_length: {}", value_length);
                let value = self.read(value_length as usize)?;
                let mut value_decoder = Decoder::main(value);
                let service_parameter = match service_parameter_key {
                    0 => {
                        let mut key_ids = vec![];
                        while !value_decoder.is_finished()? {
                            key_ids.push(value_decoder.u16()?);
                        }
                        ServiceParameter::MANDATORY { key_ids }
                    },
                    1 => {
                        let mut alpn_ids = vec![];
                        while !value_decoder.is_finished()? {
                            let alpn_id_length = value_decoder.u8()?;
                            eprintln!("alpn_id_length: {}", alpn_id_length);
                            let alpn_id = value_decoder.read(alpn_id_length as usize)?;
                            let mut id_decoder = Decoder::main(alpn_id);
                            let alpn_id = id_decoder.string()?;
                            id_decoder.finished()?;
                            eprintln!("alpn_id: {}", alpn_id);
                            alpn_ids.push(alpn_id);
                        }
                        ServiceParameter::ALPN { alpn_ids }
                    }
                    2 => ServiceParameter::NO_DEFAULT_ALPN,
                    3 => ServiceParameter::PORT {
                        port: value_decoder.u16()?
                    },
                    4 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv4_addr()?);
                        }
                        ServiceParameter::IPV4_HINT { hints }
                    }
                    5 => {
                        // TODO the RFC does not explicitly state that the length is one octet
                        // using one octet for consistency with ALPN
                        let length = value_decoder.u8()?;
                        let bytes = value_decoder.read(length as usize)?;
                        let mut config_list_decoder = Decoder::main(bytes);
                        let config_list = config_list_decoder.vec()?;
                        config_list_decoder.finished()?;
                        ServiceParameter::ECH_CONFIG { config_list }
                    }
                    6 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv6_addr()?);
                        }
                        ServiceParameter::IPV6_HINT { hints }
                    }
                    65535 => ServiceParameter::KEY_65535,
                    number => {
                        ServiceParameter::PRIVATE {
                            number,
                            presentation_key: format!("key{}", number).to_string(), // TODO does presentation key really make sense here?
                            wire_data: value_decoder.vec()?,
                            presentation_value: None, // FIXME should we Base64 the wire data?
                        }
                    }
                };
                value_decoder.finished()?;
                parameters.push(service_parameter);
            }
        }
        if !self.is_finished()? {
            return Err(TooManyBytes(self.bytes.len(), self.offset));
        }
        Ok(SVCB {
            name: header.domain_name,
            ttl: header.ttl,
            priority,
            target_name,
            parameters,
        })
    }

    pub(super) fn rr_https(&mut self, _: Header) -> DecodeResult<HTTPS> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use bytes::Bytes;

    use crate::decode::decoder::Decoder;
    use crate::decode::rr::enums::Header;
    use crate::DomainName;
    use crate::rr::ServiceParameter;

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#aliasform
    #[test]
    fn alias_form() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x00"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 0);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.com").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert!(result.parameters.is_empty());
        assert!(result.to_string().ends_with("0 foo.example.com."));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_use_the_ownername() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x00"); // target (root label)
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(result.target_name, DomainName::try_from(".").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert!(result.parameters.is_empty());
        assert!(result.to_string().ends_with("1 ."));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_port() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x10"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x00\x03"); // key 3 (port)
        bytes.extend_from_slice(b"\x00\x02"); // value length: 2 bytes (2 octets)
        bytes.extend_from_slice(b"\x00\x35"); // value: 53
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.com").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(result.parameters[0], ServiceParameter::PORT {port} if port == 53));
        assert!(result.to_string().ends_with("16 foo.example.com. port=53"));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_unregistered_key() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x02\x9b"); // key 667 (unregistered)
        bytes.extend_from_slice(b"\x00\x05"); // value length: 5 bytes (2 octets)
        bytes.extend_from_slice(b"hello"); // value
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.com").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 1);
        if let ServiceParameter::PRIVATE { number, presentation_key: _, wire_data: _, presentation_value: _ } = &result.parameters[0] {
            assert_eq!(*number, 667);
            // assert_eq!(presentation_value.as_ref().unwrap(), "hello");
            // FIXME should be able to present value as unquoted string
        } else {
            assert!(false, "Parameter should be an unregistered key")
        }
        // FIXME incorrect presentation of unregistered key values
    }

    // TODO: 1 foo.example.com. key667="hello\210qoo"

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_ipv6_hints() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
        bytes.extend_from_slice(b"\x00\x20"); // value length: 32 bytes (2 octets)
        bytes.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"); // first address
        bytes.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01"); // second address
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.com").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 1);
        if let ServiceParameter::IPV6_HINT { hints } = &result.parameters[0] {
            assert_eq!(hints.len(), 2);
            assert_eq!(hints[0].to_string(), "2001:db8::1".to_string());
            assert_eq!(hints[1].to_string(), "2001:db8::53:1".to_string());
        } else {
            assert!(false, "Parameter should be an IPv6 hint.");
        }
        // FIXME not quoting the IPv6 hints
        // assert!(result.to_string().ends_with("1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\""));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_ipv6_in_ipv4_mapped_ipv6_format() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
        bytes.extend_from_slice(b"\x00\x10"); // value length: 16 bytes (2 octets)
        bytes.extend_from_slice(b"\x20\x01\x0d\xb8\xff\xff\xff\xff\xff\xff\xff\xff\xc6\x33\x64\x64"); // address
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(result.target_name, DomainName::try_from("example.com").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 1);
        if let ServiceParameter::IPV6_HINT { hints } = &result.parameters[0] {
            assert_eq!(hints.len(), 1);
            assert_eq!(hints[0], Ipv6Addr::from_str("2001:db8:ffff:ffff:ffff:ffff:198.51.100.100").unwrap());
        } else {
            assert!(false, "Parameter should be an IPv6 hint.");
        }
        // FIXME not quoting the IPv6 hints
        // assert!(result.to_string().ends_with("1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\""));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_multiple_parameters() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x10"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03org\x00"); // target
        bytes.extend_from_slice(b"\x00\x00"); // key 0 (mandatory)
        bytes.extend_from_slice(b"\x00\x02"); // value length: 2 bytes (2 octets)
        bytes.extend_from_slice(b"\x00\x01"); // value: key 1
        bytes.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
        bytes.extend_from_slice(b"\x00\x09"); // alpn value length: 9 bytes (2 octets)
        bytes.extend_from_slice(b"\x02"); // alpn[0] length: 2 bytes (1 octet)
        bytes.extend_from_slice(b"h2"); // alpn[0] = h2
        bytes.extend_from_slice(b"\x05"); // alpn[1] length: 5 bytes (1 octet)
        bytes.extend_from_slice(b"h3-19"); // alpn[1] = h3-19
        bytes.extend_from_slice(b"\x00\x04"); // key 4 (IPv4 hint)
        bytes.extend_from_slice(b"\x00\x04"); // hint length: 4 bytes (2 octets)
        bytes.extend_from_slice(b"\xc0\x00\x02\x01"); // IPv4 address
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.org").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 3);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::MANDATORY{ key_ids } if key_ids.len() == 1 && key_ids[ 0 ] == 1 ));
        assert!(matches!(&result.parameters[1],
            ServiceParameter::ALPN { alpn_ids } if alpn_ids.len() == 2 && alpn_ids[0] == "h2" && alpn_ids[1] == "h3-19"));
        assert!(matches!(&result.parameters[2],
            ServiceParameter::IPV4_HINT { hints } if hints.len() == 1 && hints[0] == Ipv4Addr::from_str("192.0.2.1").unwrap()));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn service_form_escaped_presentation_format() {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x10"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03org\x00"); // target
        bytes.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
        bytes.extend_from_slice(b"\x00\x0c"); // param length 12
        bytes.extend_from_slice(b"\x08"); // alpn[0] length 8
        bytes.extend_from_slice(b"f\\oo,bar"); // alpn[0]
        bytes.extend_from_slice(b"\x02"); // alpn[1] length 2
        bytes.extend_from_slice(b"h2"); // alpn[1]

        let mut decoder = Decoder::main(Bytes::from(bytes));

        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_svcb(header).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(result.target_name, DomainName::try_from("foo.example.org").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(result.name, DomainName::try_from("test.example.com").unwrap());
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::ALPN { alpn_ids } if alpn_ids.len() == 2 && alpn_ids[0] == "f\\oo,bar" && alpn_ids[1] == "h2"));
    }
}