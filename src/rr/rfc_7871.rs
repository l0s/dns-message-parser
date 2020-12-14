use std::cmp::max;
use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

const MASK: u8 = 0b1111_1111;

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Address::Ipv4(ipv4_addr) => ipv4_addr.fmt(f),
            Address::Ipv6(ipv6_addr) => ipv6_addr.fmt(f),
        }
    }
}

impl Address {
    pub fn get_address_number(&self) -> AddressNumber {
        match self {
            Address::Ipv4(_) => AddressNumber::Ipv4,
            Address::Ipv6(_) => AddressNumber::Ipv6,
        }
    }
}

try_from_enum_to_integer_without_display! {
    #[repr(u16)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum AddressNumber {
        Ipv4 = 0x0001,
        Ipv6 = 0x0002,
    }
}

impl Display for AddressNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            AddressNumber::Ipv4 => write!(f, "IPv4"),
            AddressNumber::Ipv6 => write!(f, "IPv6"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ECSError {
    #[error("Prefix length is not between 0 and 32: {0}")]
    Ipv4Prefix(u8),
    #[error("IPv4 {0} does not fit {1} mask")]
    Ipv4Mask(Ipv4Addr, u8),
    #[error("Prefix length is not between 0 and 128: {0}")]
    Ipv6Prefix(u8),
    #[error("IPv6 {0} does not fit {1} mask")]
    Ipv6Mask(Ipv6Addr, u8),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ECS {
    pub(crate) source_prefix_length: u8,
    pub(crate) scope_prefix_length: u8,
    pub(crate) address: Address,
}

fn check_ipv4_addr(ipv4_addr: &Ipv4Addr, prefix_length: u8) -> Result<(), ECSError> {
    match 32.cmp(&prefix_length) {
        Ordering::Less => Err(ECSError::Ipv4Prefix(prefix_length)),
        Ordering::Equal => Ok(()),
        Ordering::Greater => {
            let octects = ipv4_addr.octets();
            let index = (prefix_length / 8) as usize;
            let remain = prefix_length % 8;

            if (octects[index] & (MASK >> remain)) != 0 {
                return Err(ECSError::Ipv4Mask(*ipv4_addr, prefix_length));
            }

            let (_, octects_right) = octects.split_at(index + 1);
            for b in octects_right {
                if *b != 0 {
                    return Err(ECSError::Ipv4Mask(*ipv4_addr, prefix_length));
                }
            }

            Ok(())
        }
    }
}

fn check_ipv6_addr(ipv6_addr: &Ipv6Addr, prefix_length: u8) -> Result<(), ECSError> {
    match 128.cmp(&prefix_length) {
        Ordering::Less => Err(ECSError::Ipv6Prefix(prefix_length)),
        Ordering::Equal => Ok(()),
        Ordering::Greater => {
            let octects = ipv6_addr.octets();
            let index = (prefix_length / 8) as usize;
            let remain = prefix_length % 8;

            if (octects[index] & (MASK >> remain)) != 0 {
                return Err(ECSError::Ipv6Mask(*ipv6_addr, prefix_length));
            }

            let (_, octects_right) = octects.split_at(index + 1);
            for b in octects_right {
                if *b != 0 {
                    return Err(ECSError::Ipv6Mask(*ipv6_addr, prefix_length));
                }
            }

            Ok(())
        }
    }
}

impl ECS {
    fn check_addr(&self) -> Result<(), ECSError> {
        let prefix_length = self.get_prefix_length();
        match &self.address {
            Address::Ipv4(ipv4_addr) => check_ipv4_addr(ipv4_addr, prefix_length)?,
            Address::Ipv6(ipv6_addr) => check_ipv6_addr(ipv6_addr, prefix_length)?,
        }

        Ok(())
    }

    pub fn new(
        source_prefix_length: u8,
        scope_prefix_length: u8,
        address: Address,
    ) -> Result<ECS, ECSError> {
        let ecs = ECS {
            source_prefix_length,
            scope_prefix_length,
            address,
        };

        ecs.check_addr()?;

        Ok(ecs)
    }

    #[inline]
    pub fn get_prefix_length(&self) -> u8 {
        max(self.source_prefix_length, self.scope_prefix_length)
    }
}

impl Display for ECS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {}",
            self.source_prefix_length, self.scope_prefix_length, self.address
        )
    }
}
