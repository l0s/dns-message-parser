use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::DomainName;
use crate::rr::draft_ietf_dnsop_svcb_https::ServiceBindingMode::{Alias, Service};
use crate::rr::{ToType, Type};

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
    // TODO ensure sorted, TODO ensure no duplicate keys
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
        write!(f,
               "{} {} IN {} {} {}",
               self.name, self.ttl, record_type, self.priority, self.target_name)?;
        self.parameters.iter().map(|parameter| -> FmtResult {
            write!(f, " ")?;
            parameter.fmt(f)
        }).collect()
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceParameter {
    /// Mandatory keys in this resource record (service mode only)
    MANDATORY {
        /// the key IDs the client must support in order for this resource record to function properly
        /// RFC section 7
        key_ids: Vec<u16>
    },
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
    /// FIXME this has been renamed to "ech"
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
            ServiceParameter::MANDATORY { .. } => 0,
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

    pub fn get_presentation_name(&self) -> String { // TODO can I return &str?
        ServiceParameter::id_to_presentation_name(self.get_registered_number())
    }

    fn id_to_presentation_name(id: u16) -> String { // TODO can I return &str?
        match id {
            0 => "mandatory".to_string(),
            1 => "alpn".to_string(),
            2 => "no-default-alpn".to_string(),
            3 => "port".to_string(),
            4 => "ipv4hint".to_string(),
            5 => "echconfig".to_string(),
            6 => "ipv6hint".to_string(),
            65535 => "reserved".to_string(),
            // TODO handle invalid keys [7, 65280)
            number => format!("key{}", number).to_string(),
        }
    }
}

impl Display for ServiceParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceParameter::MANDATORY { key_ids } => {
                let mut key_ids = key_ids.clone();
                key_ids.sort();
                let mandatory_keys = key_ids.iter()
                    .map(|id| ServiceParameter::id_to_presentation_name(*id))
                    .collect::<Vec<String>>()
                    .join(",");

                write!(f, "mandatory={}", mandatory_keys)
            }
            ServiceParameter::ALPN { alpn_ids } => {
                write!(f, "{}={}", self.get_presentation_name(), alpn_ids.join(","))
            }
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
            }
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
            }
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

    use crate::{Dns, DomainName, Flags, Opcode, RCode};
    use crate::question::{QClass, QType, Question};
    use crate::rr::{RR, ServiceBinding};

    #[test]
    fn encode_decode_alias() {
        // given
        let domain_name = DomainName::try_from("_8443._foo.api.example.com").unwrap();
        let target_name = DomainName::try_from("svc4.example.net").unwrap();

        let binding = ServiceBinding {
            name: domain_name.to_owned(),
            ttl: 7200,
            priority: 0,
            target_name,
            parameters: vec![],
            https: false,
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
            additionals: vec![],
        };

        // when
        let encoded = dns.encode().unwrap();

        // then
        let decoded = Dns::decode(encoded.freeze()).unwrap();
        assert_eq!(dns.to_string(), decoded.to_string());
    }
}