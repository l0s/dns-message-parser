use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use base64;

use crate::rr::draft_ietf_dnsop_svcb_https::ServiceBindingMode::{Alias, Service};
use crate::rr::{ToType, Type};
use crate::DomainName;

/// A Service Binding record for locating alternative endpoints for a service.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceBinding {
    pub name: DomainName,
    pub ttl: u32,

    // The class is always IN (Internet, 0x0001)
    /// The `SvcPriority` field, a value between 0 and 65535
    /// SVCB resource records with a smaller priority SHOULD be given priority over resource records
    /// with a larger value.
    pub priority: u16,
    pub target_name: DomainName,
    pub parameters: Vec<ServiceParameter>,
    /// Indicates whether or not this is an HTTPS record (RFC section 8)
    pub https: bool,
}

impl ToType for ServiceBinding {
    fn to_type(&self) -> Type {
        if self.https {
            Type::HTTPS
        } else {
            Type::SVCB
        }
    }
}

/// The modes inferred from the `SvcPriority` field
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceBindingMode {
    /// "go to the target name and do another service binding query"
    /// enables apex aliasing for participating clients
    Alias,

    /// Indicates that this record contains an arbitrary (IANA controlled) key value data store
    /// The record contains anything the client _may_ need to know in order to connect to the server.
    Service,
}

impl Display for ServiceBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let record_type = if self.https { "HTTPS" } else { "SVCB" };
        write!(
            f,
            "{} {} IN {} {} {}",
            self.name, self.ttl, record_type, self.priority, self.target_name
        )?;
        let mut parameters = self.parameters.clone();
        parameters.sort();
        parameters
            .iter()
            .map(|parameter| -> FmtResult {
                write!(f, " ")?;
                parameter.fmt(f)
            })
            .collect()
    }
}

impl ServiceBinding {
    pub fn mode(&self) -> ServiceBindingMode {
        if self.priority == 0 {
            Alias
        } else {
            Service
        }
    }
}

#[derive(Debug, Clone, Eq, PartialOrd)]
pub enum ServiceParameter {
    /// Mandatory keys in this resource record (service mode only)
    MANDATORY {
        /// the key IDs the client must support in order for this resource record to function properly
        /// RFC section 7
        key_ids: Vec<u16>,
    },
    /// Additional supported protocols
    ALPN {
        /// The default set of ALPNs, which SHOULD NOT be empty, e.g. "h3", "h2", "http/1.1".
        alpn_ids: Vec<String>,
    },
    /// No support for default protocol
    ///
    /// When this is specified in a resource record, `ALPN` must also be specified in order to be
    /// "self-consistent".
    NO_DEFAULT_ALPN,
    /// Port for alternative endpoint
    PORT { port: u16 },
    /// IPv4 address hints
    IPV4_HINT { hints: Vec<Ipv4Addr> },
    /// Encrypted ClientHello information (RFC Section 9)
    ///
    /// This conveys the ECH configuration of an alternative endpoint.
    ECH { config_list: Vec<u8> },
    /// IPv6 address hints
    IPV6_HINT { hints: Vec<Ipv6Addr> },
    /// Private use keys 65280-65534
    PRIVATE { number: u16, wire_data: Vec<u8> },
    /// Reserved ("Invalid key")
    KEY_65535,
}

impl PartialEq for ServiceParameter {
    fn eq(&self, other: &Self) -> bool {
        self.get_registered_number()
            .eq(&other.get_registered_number())
    }
}

impl Hash for ServiceParameter {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u16(self.get_registered_number())
    }
}

impl Ord for ServiceParameter {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_registered_number()
            .cmp(&other.get_registered_number())
    }
}

impl ServiceParameter {
    pub fn get_registered_number(&self) -> u16 {
        match self {
            ServiceParameter::MANDATORY { .. } => 0,
            ServiceParameter::ALPN { .. } => 1,
            ServiceParameter::NO_DEFAULT_ALPN => 2,
            ServiceParameter::PORT { .. } => 3,
            ServiceParameter::IPV4_HINT { .. } => 4,
            ServiceParameter::ECH { .. } => 5,
            ServiceParameter::IPV6_HINT { .. } => 6,
            ServiceParameter::PRIVATE {
                number,
                wire_data: _,
            } => *number,
            ServiceParameter::KEY_65535 => 65535,
        }
    }

    fn id_to_presentation_name(id: u16) -> String {
        match id {
            0 => "mandatory".to_string(),
            1 => "alpn".to_string(),
            2 => "no-default-alpn".to_string(),
            3 => "port".to_string(),
            4 => "ipv4hint".to_string(),
            5 => "ech".to_string(),
            6 => "ipv6hint".to_string(),
            65535 => "reserved".to_string(),
            number => format!("key{}", number),
        }
    }
}

/// Escape backslashes and commas in an ALPN ID
fn escape_alpn(alpn: &String) -> String {
    let mut result = String::new();
    for char in alpn.chars() {
        if char == '\\' {
            result.push_str("\\\\\\");
        } else if char == ',' {
            result.push('\\');
        }
        result.push(char);
    }
    result
}

impl Display for ServiceParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceParameter::MANDATORY { key_ids } => {
                let mut key_ids = key_ids.clone();
                key_ids.sort();
                let mandatory_keys = key_ids
                    .iter()
                    .map(|id| ServiceParameter::id_to_presentation_name(*id))
                    .collect::<Vec<String>>()
                    .join(",");

                write!(f, "mandatory={}", mandatory_keys)
            }
            ServiceParameter::ALPN { alpn_ids } => {
                let mut escape = false;
                let mut escaped_ids = vec![];
                for id in alpn_ids {
                    let escaped = escape_alpn(id);
                    if escaped != *id {
                        escape |= true;
                    }
                    escaped_ids.push(escaped);
                }
                let value = escaped_ids.join(",");
                if escape {
                    write!(f, "alpn=\"{}\"", value)
                } else {
                    write!(f, "alpn={}", value)
                }
            }
            ServiceParameter::NO_DEFAULT_ALPN => write!(f, "no-default-alpn"),
            ServiceParameter::PORT { port } => write!(f, "port={}", port),
            ServiceParameter::IPV4_HINT { hints } => {
                write!(
                    f,
                    "ipv4hint={}",
                    hints
                        .iter()
                        .map(|hint| hint.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
            ServiceParameter::ECH { config_list } => {
                write!(f, "ech={}", base64::encode(config_list))
            }
            ServiceParameter::IPV6_HINT { hints } => {
                write!(
                    f,
                    "ipv6hint=\"{}\"",
                    hints
                        .iter()
                        .map(|hint| hint.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
            ServiceParameter::PRIVATE { number, wire_data } => {
                let key = format!("key{}", number);
                let value = String::from_utf8(wire_data.clone());
                if let Ok(value) = value {
                    write!(f, "{}={}", key, value)
                } else {
                    let mut escaped = vec![];
                    for byte in wire_data {
                        if *byte < b'0'
                            || (*byte > b'9' && *byte < b'A')
                            || (*byte > b'Z' && *byte < b'a')
                            || *byte > b'z'
                        {
                            escaped.extend_from_slice(format!("\\{}", *byte).as_bytes());
                        } else {
                            escaped.push(*byte);
                        }
                    }
                    if let Ok(value) = String::from_utf8(escaped) {
                        write!(f, "{}=\"{}\"", key, value)
                    } else {
                        write!(f, "{}=\"{}\"", key, base64::encode(wire_data))
                    }
                }
            }
            ServiceParameter::KEY_65535 => write!(f, "reserved"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use crate::rr::{ServiceBinding, ServiceParameter};
    use crate::DomainName;

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#aliasform
    #[test]
    fn alias_form() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 7200,
            priority: 0, // alias
            target_name,
            parameters: vec![],
            https: true,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.com. 7200 IN HTTPS 0 foo.example.com.".to_string()
        );
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn use_the_ownername() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::default();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 300,
            priority: 1,
            target_name,
            parameters: vec![],
            https: false,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(result, "example.com. 300 IN SVCB 1 .");
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn map_port() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 7200,
            priority: 16,
            target_name,
            parameters: vec![ServiceParameter::PORT { port: 53 }],
            https: true,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.com. 7200 IN HTTPS 16 foo.example.com. port=53"
        );
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn unregistered_key_value() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 300,
            priority: 1,
            target_name,
            parameters: vec![ServiceParameter::PRIVATE {
                number: 667,
                wire_data: b"hello".to_vec(),
            }],
            https: false,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.com. 300 IN SVCB 1 foo.example.com. key667=hello"
        );
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn unregistered_key_escaped_value() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 300,
            priority: 1,
            target_name,
            parameters: vec![ServiceParameter::PRIVATE {
                number: 667,
                wire_data: b"hello\xd2qoo".to_vec(),
            }],
            https: true,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.com. 300 IN HTTPS 1 foo.example.com. key667=\"hello\\210qoo\""
        );
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn ipv6_hints() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 7200,
            priority: 1,
            target_name,
            parameters: vec![ServiceParameter::IPV6_HINT {
                hints: vec![
                    Ipv6Addr::from_str("2001:db8::1").unwrap(),
                    Ipv6Addr::from_str("2001:db8::53:1").unwrap(),
                ],
            }],
            https: false,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.com. 7200 IN SVCB 1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\""
        );
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn ipv6_hint_in_ipv4_mapped_ipv6_format() {
        // given
        let domain_name = DomainName::try_from("example.com").unwrap();
        let target_name = DomainName::try_from("foo.example.com").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 300,
            priority: 1,
            target_name,
            parameters: vec![ServiceParameter::IPV6_HINT {
                hints: vec![
                    Ipv6Addr::from_str("2001:db8:ffff:ffff:ffff:ffff:198.51.100.100").unwrap(),
                ],
            }],
            https: true,
        };

        // when
        let result = service_binding.to_string();

        // then
        // note IPv6 display rules are already well-defined so not changing that here
        // this behaviour conforms to the robustness principle
        assert_eq!(result,
                   "example.com. 300 IN HTTPS 1 foo.example.com. ipv6hint=\"2001:db8:ffff:ffff:ffff:ffff:c633:6464\"");
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn multiple_parameters_in_wrong_order() {
        // given
        let domain_name = DomainName::try_from("example.org").unwrap();
        let target_name = DomainName::try_from("foo.example.org").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 7200,
            priority: 16,
            target_name,
            parameters: vec![
                // the parameters are deliberately specified in the wrong order
                // they will be sorted correctly in the presentation format
                ServiceParameter::ALPN {
                    alpn_ids: vec!["h2".to_string(), "h3-19".to_string()],
                },
                ServiceParameter::MANDATORY {
                    key_ids: vec![4, 1], // ipv4hint and alpn are mandatory
                },
                ServiceParameter::IPV4_HINT {
                    hints: vec![Ipv4Addr::from_str("192.0.2.1").unwrap()],
                },
            ],
            https: false,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(result,
                   "example.org. 7200 IN SVCB 16 foo.example.org. mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1");
    }

    /// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
    #[test]
    fn alpn_with_escaped_values() {
        // given
        let domain_name = DomainName::try_from("example.org").unwrap();
        let target_name = DomainName::try_from("foo.example.org").unwrap();
        let service_binding = ServiceBinding {
            name: domain_name,
            ttl: 300,
            priority: 16,
            target_name,
            parameters: vec![ServiceParameter::ALPN {
                alpn_ids: vec!["f\\oo,bar".to_string(), "h2".to_string()],
            }],
            https: true,
        };

        // when
        let result = service_binding.to_string();

        // then
        assert_eq!(
            result,
            "example.org. 300 IN HTTPS 16 foo.example.org. alpn=\"f\\\\\\\\oo\\,bar,h2\""
        );
    }
}
