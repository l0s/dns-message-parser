use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::{DomainName, EncodeResult};
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
    pub parameters: Vec<ServiceParameter>,
}
impl_to_type!(SVCB);

/// The modes inferred from the `SvcPriority` field
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
               self.name, self.ttl, self.priority, self.target_name);
        self.parameters.iter().for_each(|parameter| -> () {
            write!(f, " ");
            parameter.fmt(f);
        });
        Ok(())
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
    pub parameters: Vec<ServiceParameter>,
}
impl_to_type!(HTTPS);

impl Display for HTTPS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f,
               "{} {} IN HTTPS {} {}",
               self.name, self.ttl, self.priority, self.target_name);
        self.parameters.iter().for_each(|parameter| -> () {
            write!(f, " ");
            parameter.fmt(f);
        });
        Ok(())
    }
}

pub enum ServiceParameterKey {
    KEY_0,
    ALPN,
    PORT,
    ESNI_KEYS,
    IPV4_HINT,
    KEY_5,
    IPV6_HINT,
    PRIVATE(u16),
    KEY_65535,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceParameter {
    /// A SvcParamKey. These are lower-case alphanumeric strings.
    pub key: String, // FIXME key constraints
    pub value: Option<String>,
}

impl Display for ServiceParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.value {
            None => write!(f, "{}", self.key),
            Some(value) => write!(f, "{}={}", self.key, value),
        }
    }
}