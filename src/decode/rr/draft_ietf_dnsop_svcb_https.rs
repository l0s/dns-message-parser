use crate::decode::Decoder;
use crate::DecodeResult;
use crate::rr::{HTTPS, SVCB, ServiceParameter};

use super::Header;
use crate::decode::error::DecodeError::TooManyBytes;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_svcb(&mut self, header: Header) -> DecodeResult<SVCB> {
        let priority = self.u16()?;
        let target_name = self.domain_name()?;
        let mut parameters = vec![];
        if priority != 0 {
            while !self.is_finished()? {
                let service_parameter_key = self.u16()?;
                let value_length = self.u16()?;
                let value = self.read(value_length as usize)?;
                let mut value_decoder = Decoder {
                    parent: None,
                    bytes: value,
                    offset: 0
                };
                let service_parameter = match service_parameter_key {
                    0 => ServiceParameter::MANDATORY,
                    1 => {
                        let mut alpn_ids = vec![];
                        while !value_decoder.is_finished()? {
                            let alpn_id_length = value_decoder.u8()?;
                            let mut id_decoder = value_decoder.sub(alpn_id_length as u16)?;
                            let alpn_id = id_decoder.string()?;
                            alpn_ids.push(alpn_id);
                            id_decoder.finished()?;
                        }
                        ServiceParameter::ALPN { alpn_ids }
                    },
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
                    },
                    5 => {
                        // TODO the RFC does not explicitly state that the length is one octet
                        // using one octet for consistency with ALPN
                        let length = value_decoder.u8()?;
                        let mut config_list_decoder = value_decoder.sub(length as u16)?;
                        let config_list = config_list_decoder.vec()?;
                        config_list_decoder.finished()?;
                        ServiceParameter::ECH_CONFIG { config_list }
                    },
                    6 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv6_addr()?);
                        }
                        ServiceParameter::IPV6_HINT { hints }
                    },
                    65535 => ServiceParameter::KEY_65535,
                    number => {
                        ServiceParameter::PRIVATE {
                            number,
                            presentation_key: format!("key{}", number).to_string(), // TODO does presentation key really make sense here?
                            wire_data: value_decoder.vec()?,
                            presentation_value: None // FIXME should we Base64 the wire data?
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

    pub(super) fn rr_https(&mut self, header: Header) -> DecodeResult<HTTPS> {
        let priority = self.u16()?;
        let target_name = self.domain_name()?;
        let mut parameters = vec![];
        if priority != 0 {
            while !self.is_finished()? {
                let service_parameter_key = self.u16()?;
                let value_length = self.u16()?;
                let value = self.read(value_length as usize)?;
                let mut value_decoder = Decoder {
                    parent: None,
                    bytes: value,
                    offset: 0
                };
                let service_parameter = match service_parameter_key {
                    0 => ServiceParameter::MANDATORY,
                    1 => {
                        let mut alpn_ids = vec![];
                        while !value_decoder.is_finished()? {
                            let alpn_id_length = value_decoder.u8()?;
                            let mut id_decoder = value_decoder.sub(alpn_id_length as u16)?;
                            let alpn_id = id_decoder.string()?;
                            alpn_ids.push(alpn_id);
                            id_decoder.finished()?;
                        }
                        ServiceParameter::ALPN { alpn_ids }
                    },
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
                    },
                    5 => {
                        // TODO the RFC does not explicitly state that the length is one octet
                        // using one octet for consistency with ALPN
                        let length = value_decoder.u8()?;
                        let mut config_list_decoder = value_decoder.sub(length as u16)?;
                        let config_list = config_list_decoder.vec()?;
                        config_list_decoder.finished()?;
                        ServiceParameter::ECH_CONFIG { config_list }
                    },
                    6 => {
                        let mut hints = vec![];
                        while !value_decoder.is_finished()? {
                            hints.push(value_decoder.ipv6_addr()?);
                        }
                        ServiceParameter::IPV6_HINT { hints }
                    },
                    65535 => ServiceParameter::KEY_65535,
                    number => {
                        ServiceParameter::PRIVATE {
                            number,
                            presentation_key: format!("key{}", number).to_string(), // TODO does presentation key really make sense here?
                            wire_data: value_decoder.vec()?,
                            presentation_value: None // FIXME should we Base64 the wire data?
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
        Ok(HTTPS {
            name: header.domain_name,
            ttl: header.ttl,
            priority,
            target_name,
            parameters,
        })
    }
}