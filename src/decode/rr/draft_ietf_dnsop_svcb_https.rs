use crate::decode::error::DecodeError::TooManyBytes;
use crate::decode::Decoder;
use crate::rr::{ServiceBinding, ServiceParameter};
use crate::DecodeResult;

use super::Header;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    /// Decode a Service Binding (SVCB or HTTP) resource record
    ///
    /// Preconditions
    /// * The header and question sections should have already been decoded. Specifically, index of
    ///   any previously-identified domain names must already be captured.
    ///
    /// Parameters
    /// - `header` - the header that precedes the question section
    /// - `https` - true for `HTTPS` resource records, false for `SVCB`
    pub(super) fn rr_service_binding(
        &mut self,
        header: Header,
        https: bool,
    ) -> DecodeResult<ServiceBinding> {
        let priority = self.u16()?;
        let target_name = self.domain_name()?;
        let mut parameters = vec![];
        if priority != 0 {
            while !self.is_finished()? {
                let service_parameter_key = self.u16()?;
                let value_length = self.u16()?;
                let value = self.read(value_length as usize)?;
                let mut value_decoder = Decoder::main(value);
                let service_parameter = match service_parameter_key {
                    0 => {
                        let mut key_ids = vec![];
                        while !value_decoder.is_finished()? {
                            key_ids.push(value_decoder.u16()?);
                        }
                        ServiceParameter::MANDATORY { key_ids }
                    }
                    1 => {
                        let mut alpn_ids = vec![];
                        while !value_decoder.is_finished()? {
                            alpn_ids.push(value_decoder.string()?);
                        }
                        ServiceParameter::ALPN { alpn_ids }
                    }
                    2 => ServiceParameter::NO_DEFAULT_ALPN,
                    3 => ServiceParameter::PORT {
                        port: value_decoder.u16()?,
                    },
                    4 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv4_addr()?);
                        }
                        ServiceParameter::IPV4_HINT { hints }
                    }
                    5 => {
                        // Note the RFC does not explicitly state that the length is two octets
                        // "In wire format, the value of the parameter is an ECHConfigList [ECH],
                        // including the redundant length prefix." - RFC Section 9
                        let _ = value_decoder.u16()?; // length
                        let config_list = value_decoder.vec()?;
                        ServiceParameter::ECH { config_list }
                    }
                    6 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv6_addr()?);
                        }
                        ServiceParameter::IPV6_HINT { hints }
                    }
                    65535 => ServiceParameter::KEY_65535,
                    number => ServiceParameter::PRIVATE {
                        number,
                        wire_data: value_decoder.vec()?,
                    },
                };
                value_decoder.finished()?;
                parameters.push(service_parameter);
            }
        }
        if !self.is_finished()? {
            return Err(TooManyBytes(self.bytes.len(), self.offset));
        }
        parameters.sort();
        Ok(ServiceBinding {
            name: header.domain_name,
            ttl: header.ttl,
            priority,
            target_name,
            parameters,
            https,
        })
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
    use crate::rr::ServiceParameter;
    use crate::DomainName;

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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 0);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert!(result.parameters.is_empty());
        assert!(result.to_string().ends_with("0 foo.example.com."));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn use_the_ownername() {
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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(result.target_name, DomainName::try_from(".").unwrap());
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert!(result.parameters.is_empty());
        assert!(result.to_string().ends_with("1 ."));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn map_port() {
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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(result.parameters[0], ServiceParameter::PORT {port} if port == 53));
        assert!(result.to_string().ends_with("16 foo.example.com. port=53"));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn unregistered_key() {
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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::PRIVATE { number, wire_data, } if *number == 667
                && String::from_utf8(wire_data.clone()).unwrap() == *"hello"))
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn unregistered_key_escaped_value() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x02\x9b"); // key 667 (unregistered)
        bytes.extend_from_slice(b"\x00\x09"); // value length: 9 bytes (2 octets)
        bytes.extend_from_slice(b"hello\xd2qoo"); // value
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::PRIVATE { number, wire_data, } if *number == 667
                && wire_data.as_slice() == b"hello\xd2qoo"));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn ipv6_hints() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
        bytes.extend_from_slice(b"\x00\x20"); // value length: 32 bytes (2 octets)
        bytes
            .extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"); // first address
        bytes
            .extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01"); // second address
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::IPV6_HINT { hints } if hints.len() == 2
                && hints[0] == Ipv6Addr::from_str("2001:db8::1").unwrap()
                && hints[1] == Ipv6Addr::from_str("2001:db8::53:1").unwrap()));
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn ipv6_in_ipv4_mapped_ipv6_format() {
        // given
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(b"\x00\x01"); // priority
        bytes.extend_from_slice(b"\x07example\x03com\x00"); // target
        bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
        bytes.extend_from_slice(b"\x00\x10"); // value length: 16 bytes (2 octets)
        bytes
            .extend_from_slice(b"\x20\x01\x0d\xb8\xff\xff\xff\xff\xff\xff\xff\xff\xc6\x33\x64\x64"); // address
        let mut decoder = Decoder::main(Bytes::from(bytes));
        let header = Header {
            domain_name: DomainName::try_from("test.example.com").unwrap(),
            class: 1,
            ttl: 7200,
        };

        // when
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 1);
        assert_eq!(
            result.target_name,
            DomainName::try_from("example.com").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
             ServiceParameter::IPV6_HINT { hints } if hints.len() == 1 && hints[0] == Ipv6Addr::from_str("2001:db8:ffff:ffff:ffff:ffff:198.51.100.100").unwrap()))
    }

    /// https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn multiple_parameters() {
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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.org").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
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
    fn escaped_presentation_format() {
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
        let result = decoder.rr_service_binding(header, false).unwrap();

        // then
        assert_eq!(result.priority, 16);
        assert_eq!(
            result.target_name,
            DomainName::try_from("foo.example.org").unwrap()
        );
        assert_eq!(result.ttl, 7200);
        assert_eq!(
            result.name,
            DomainName::try_from("test.example.com").unwrap()
        );
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(&result.parameters[0],
            ServiceParameter::ALPN { alpn_ids } if alpn_ids.len() == 2 && alpn_ids[0] == "f\\oo,bar" && alpn_ids[1] == "h2"));
    }
}
