use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::DomainName;
use crate::rr::draft_ietf_dnsop_svcb_https::ServiceBindingMode::{Alias, Service};

/// FIXME
/// A Service Binding record
/// This bootstraps optimal connections from a single DNS query
/// Looks similar to SRV
/// e.g. _Port._Scheme.Name TTL IN SVCB SvcPriority TargetName [SvcParams...]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SVCB {
    pub name: DomainName,
    pub ttl: u32,

    // The class is always IN, Internet

    /// The `SvcPriority` field, a value between 0 and 65535
    /// SVCB resource records with a smaller priority SHOULD be given priority over resource records
    /// with a larger value.
    pub priority: u16,
    pub target_name: DomainName,
    pub parameters: Vec<ServiceParameter>, // TODO ensure sorted, TODO ensure no duplicate keys
}
impl_to_type!(SVCB);

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

impl Display for SVCB {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f,
               "{} {} IN SVCB {} {}",
               self.name, self.ttl, self.priority, self.target_name)?;
        self.parameters.iter().map(|parameter| -> FmtResult {
            write!(f, " ")?;
            parameter.fmt(f)
        }).collect()
    }
}

impl SVCB {
    pub fn mode(&self) -> ServiceBindingMode {
        if self.priority == 0 {
            Alias
        } else {
            Service
        }
    }
}

/// FIXME
/// An SVCB-compatible resource record type specialised for HTTPS
/// It does not use the underscore prefix scheme from HTTPS, improving compatibility with wildcard
/// domains, and is compatible with existing CNAME delegations.
/// It indicates that the origin defaults to HTTPS.
///
/// Encodes the "authority" portion of a URI (e.g. scheme, name, port, and more)
/// protocol is skipped if it is https
/// DNS servers treat SVCB and HTTPs identically
///
/// Specification does not rely on DNSSEC. Clients should always treat HTTPS records as untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HTTPS {
    pub name: DomainName,
    pub ttl: u32,

    // The class is always IN, Internet

    /// The SvcPriority field, a value between 0 and 65535
    pub priority: u16,
    pub target_name: DomainName,
    pub parameters: Vec<ServiceParameter>, // TODO ensure sorted, TODO ensure no duplicate keys
}
impl_to_type!(HTTPS);

impl Display for HTTPS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f,
               "{} {} IN HTTPS {} {}",
               self.name, self.ttl, self.priority, self.target_name)?;
        self.parameters.iter().map(|parameter| -> FmtResult {
            write!(f, " ")?;
            parameter.fmt(f)
        }).collect()
    }
}

impl HTTPS {
    pub fn mode(&self) -> ServiceBindingMode {
        if self.priority == 0 {
            Alias
        } else {
            Service
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceParameter {
    /// Mandatory keys in this resource record
    MANDATORY,
    /// Additional supported protocols
    ALPN {
        /// The default set of ALPNs, which SHOULD NOT be empty, e.g. "h3", "h2", "http/1.1".
        alpn_ids: Vec<String>
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
    /// Encrypted ClientHello information
    ///
    /// TODO: refer to section 9 in the RFC
    ECH_CONFIG { config_list: Vec<u8> },
    /// IPv6 address hints
    IPV6_HINT { hints: Vec<Ipv6Addr> },
    /// Private use keys 65280-65534
    PRIVATE {
        number: u16,
        presentation_key: String,
        wire_data: Vec<u8>,
        presentation_value: Option<String>,
    },
    /// Reserved ("Invalid key")
    KEY_65535,
}

impl ServiceParameter {
    pub fn get_registered_number(&self) -> u16 {
        match self {
            ServiceParameter::MANDATORY => 0,
            ServiceParameter::ALPN { .. } => 1,
            ServiceParameter::NO_DEFAULT_ALPN => 2,
            ServiceParameter::PORT { .. } => 3,
            ServiceParameter::IPV4_HINT { .. } => 4,
            ServiceParameter::ECH_CONFIG { .. } => 5,
            ServiceParameter::IPV6_HINT { .. } => 6,
            ServiceParameter::PRIVATE { number, presentation_key: _, wire_data: _, presentation_value: _ } => *number,
            ServiceParameter::KEY_65535 => 65535,
        }
    }

    pub fn get_wire_data(&self) -> Vec<u8> { // TODO sort out the return value, should we just write to the encoder?
        todo!()
    }

    pub fn get_presentation_name(&self) -> &str {
        match self {
            ServiceParameter::MANDATORY => "mandatory",
            ServiceParameter::ALPN { .. } => "alpn",
            ServiceParameter::NO_DEFAULT_ALPN => "no-default-alpn",
            ServiceParameter::PORT { .. } => "port",
            ServiceParameter::IPV4_HINT { .. } => "ipv4hint",
            ServiceParameter::ECH_CONFIG { .. } => "echconfig",
            ServiceParameter::IPV6_HINT { .. } => "ipv6hint",
            ServiceParameter::PRIVATE { number: _, presentation_key, wire_data: _, presentation_value: _ } => presentation_key,
            ServiceParameter::KEY_65535 => "reserved",
        }
    }
}

impl Display for ServiceParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceParameter::MANDATORY => write!(f, "{}", self.get_presentation_name()),
            ServiceParameter::ALPN { alpn_ids } => {
                write!(f, "{}={}", self.get_presentation_name(), alpn_ids.join(","))
            },
            ServiceParameter::NO_DEFAULT_ALPN => write!(f, "{}", self.get_presentation_name()),
            ServiceParameter::PORT { port } => write!(f, "{}={}", self.get_presentation_name(), port),
            ServiceParameter::IPV4_HINT { hints } => {
                write!(f,
                       "{}={}",
                       self.get_presentation_name(),
                       hints.iter()
                           .map(|hint| hint.to_string())
                           .collect::<Vec<String>>()
                           .join(","))
            },
            ServiceParameter::ECH_CONFIG { config_list: _ } => {
                todo!()
            }
            ServiceParameter::IPV6_HINT { hints } => {
                write!(f,
                       "{}={}",
                       self.get_presentation_name(),
                       hints.iter()
                           .map(|hint| hint.to_string())
                           .collect::<Vec<String>>()
                           .join(","))
            },
            ServiceParameter::PRIVATE { number: _, presentation_key: _, wire_data: _, presentation_value } => {
                match presentation_value {
                    None => write!(f, "{}", self.get_presentation_name()),
                    Some(value) => write!(f, "{}={}", self.get_presentation_name(), value),
                }
            }
            ServiceParameter::KEY_65535 => write!(f, "{}", self.get_presentation_name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use crate::rr::{SVCB, RR};
    use crate::{DomainName, Dns, Flags, Opcode, RCode};
    use crate::question::{Question, QClass, QType};


    #[test]
    fn test() {
        // given
        let domain_name = DomainName::try_from("_8443._foo.api.example.com").unwrap();
        let target_name = DomainName::try_from("svc4.example.net").unwrap();

        let binding = SVCB {
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
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: RCode::NoError,
            },
            questions: vec![
                Question {
                    domain_name,
                    q_class: QClass::IN,
                    q_type: QType::SVCB,
                }
            ],
            answers: vec![
                RR::SVCB(binding),
            ],
            authorities: vec![],
            additionals: vec![]
        };

        // when
        let encoded = dns.encode().unwrap();

        // then
        let decoded = Dns::decode(encoded.freeze()).unwrap();
        assert_eq!(dns.to_string(), decoded.to_string());
    }
}