use bytes::Bytes;
use dns_message_parser::rr::{AddressError, Class};
use dns_message_parser::{DecodeError, Dns, Flags};

fn decode_msg_error(msg: &[u8], e: DecodeError) {
    // Decode BytesMut to message
    let bytes = Bytes::copy_from_slice(&msg[..]);
    // Decode the DNS message
    let dns = Dns::decode(bytes);
    // Check the result
    assert_eq!(dns, Err(e))
}

fn decode_flags_error(msg: &[u8], e: DecodeError) {
    // Decode BytesMut to message
    let bytes = Bytes::copy_from_slice(&msg[..]);
    // Decode the DNS message
    let flags = Flags::decode(bytes);
    // Check the result
    assert_eq!(flags, Err(e))
}

#[test]
fn flags_1() {
    let msg = b"";
    decode_flags_error(msg, DecodeError::NotEnoughBytes(0, 1));
}

#[test]
fn flags_2() {
    let msg = b"\xff";
    decode_flags_error(msg, DecodeError::Opcode(15));
}

#[test]
fn flags_3() {
    let msg = b"\x85";
    decode_flags_error(msg, DecodeError::NotEnoughBytes(1, 2));
}

#[test]
fn flags_4() {
    let msg = b"\x80\xff";
    decode_flags_error(msg, DecodeError::ZNotZeroes(64));
}

#[test]
fn flags_5() {
    let msg = b"\x80\x0f";
    decode_flags_error(msg, DecodeError::RCode(15));
}

#[test]
fn a_example_org_response_1() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x05\x0a\x00\
    \x00\x0a\x00";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(5, 4));
}

#[test]
fn a_example_org_response_2() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x02\x00\x00\x0e\x10\x00\x05\x0a\x00\
    \x00\x0a\x00";
    decode_msg_error(&msg[..], DecodeError::AClass(Class::CS));
}

#[test]
fn ns_example_org_response() {
    let msg = b"\x03\x78\x85\x80\x00\x01\x00\x02\x00\x00\x00\x02\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x00\x0e\x10\x00\x06\x03\x6e\
    \x73\x31\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x00\x0e\x10\x00\x07\x03\x6e\x73\x32\xc0\x0c\x00\
    \xc0\x29\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01\xc0\x3b\x00\x01\x00\x01\x00\
    \x00\x0e\x10\x00\x04\x0a\x00\x00\x01";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(7, 6));
}

#[test]
fn cname_example_org_response() {
    let msg = b"\xe2\x7b\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05\x63\x6e\x61\x6d\x65\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\
    \x0e\x10\x00\x03\xc0\x12\x00";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(3, 2));
}

#[test]
fn mb_example_org_response() {
    let msg = b"\x36\x8b\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x07\x00\x01\xc0\x0c\x00\x07\x00\x01\x00\x00\x0e\x10\x00\x08\x04\x6d\
    \x61\x69\x6c\xc0\x0c\x00\xc0\x29\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0c";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(8, 7));
}

#[test]
fn mg_example_org_request_error() {
    let msg = b"\x7d\x35\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x08\x00\x01\xc0\x0c\x00\x08\x00\x01\x00\x00\x0e\x10\x00\x06\x04\x6d\
    \x61\x69\x6c\xc0\x0c";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(6, 7));
}

#[test]
fn mr_example_org_response() {
    let msg = b"\xa3\xc4\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x09\x00\x01\xc0\x0c\x00\x09\x00\x01\x00\x00\x0e\x10\x00\x06\x04\x6d\
    \x61\x69\x6c\xc0\x0c";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(6, 7));
}

#[test]
fn wks_example_org_response_1() {
    let msg = b"\xd9\xc6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0b\x00\x01\xc0\x0c\x00\x0b\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(4, 5));
}

#[test]
fn wks_example_org_response_2() {
    let msg = b"\xd9\xc6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0b\x00\x01\xc0\x0c\x00\x0b\x00\x01\x00\x00\x0e\x10\x00\x08\x0a\x00\
    \x00\x0a\x06\x01";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(47, 49));
}

#[test]
fn wks_example_org_response_3() {
    let msg = b"\xd9\xc6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0b\x00\x01\xc0\x0c\x00\x0b\x00\x03\x00\x00\x0e\x10\x00\x08\x0a\x00\
    \x00\x0a\x06\x01\x00\x15";
    decode_msg_error(&msg[..], DecodeError::WKSClass(Class::CH));
}

#[test]
fn ptr_example_org_response() {
    let msg = b"\x0c\x72\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x02\x31\x30\x01\x30\x01\x30\x02\
    \x31\x30\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\
    \x00\x01\x00\x00\x0e\x10\x00\x0c\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(12, 13));
}

#[test]
fn hinfo_example_org_response_1() {
    let msg = b"\x78\x99\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0d\x00\x01\xc0\x0c\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x01\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(1, 2));
}

#[test]
fn hinfo_example_org_response_2() {
    let msg = b"\x78\x99\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0d\x00\x01\xc0\x0c\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x05\x04\x54\
    \x45\x53\x54";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(5, 6));
}

#[test]
fn hinfo_example_org_response_3() {
    let msg = b"\x78\x99\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0d\x00\x01\xc0\x0c\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x0c\x04\x54\
    \x45\x53\x54\x05\x4c\x69\x6e\x75\x78\x00";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(12, 11));
}

#[test]
fn afsdb_example_org_response_1() {
    let msg = b"\x10\x2b\x85\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x12\x00\x01\xc0\x0c\x00\x12\x00\x01\x00\x00\x0e\x10\x00\x15\x00\x01\
    \x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x0c\x00\x12\
    \x00\x01\x00\x00\x0e\x10\x00\x00\xc0\x4c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\
    \x0e";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(0, 2));
}

#[test]
fn afsdb_example_org_response_2() {
    let msg = b"\x10\x2b\x85\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x12\x00\x01\xc0\x0c\x00\x12\x00\x01\x00\x00\x0e\x10\x00\x15\x00\x01\
    \x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x0c\x00\x12\
    \x00\x01\x00\x00\x0e\x10\x00\x15\x00\x03\x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\
    \x65\x03\x6f\x72\x67\x00\xc0\x4c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0e";
    decode_msg_error(&msg[..], DecodeError::AFSDBSubtype(3));
}

#[test]
fn afsdb_example_org_response_3() {
    let msg = b"\x10\x2b\x85\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x12\x00\x01\xc0\x0c\x00\x12\x00\x01\x00\x00\x0e\x10\x00\x15\x00\x01\
    \x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x0c\x00\x12\
    \x00\x01\x00\x00\x0e\x10\x00\x15\x00\x02\x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\
    \x65\x00\x00\x00\x00\x00\xc0\x4c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0e";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(21, 17));
}

#[test]
fn soa_example_org_response_1() {
    let msg = b"\xeb\x9c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x02\x03\x6e";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(2, 4));
}

#[test]
fn soa_example_org_response_2() {
    let msg = b"\xeb\x9c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x19\x03\x6e\
    \x73\x31\x07\x65\x78\x61\x6d\x70\x6c\x65\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(25, 26));
}

#[test]
fn soa_example_org_response_3() {
    let msg = b"\xeb\x9c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x1b\x03\x6e\
    \x73\x31\xc0\x0c\x07\x65\x78\x61\x6d\x70\x6c\x65\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\
    \x67\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(27, 31));
}

#[test]
fn minfo_example_org_response_1() {
    let msg = b"\x03\x10\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0e\x00\x01\xc0\x0c\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(0, 1));
}

#[test]
fn minfo_example_org_response_2() {
    let msg = b"\x03\x10\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0e\x00\x01\xc0\x0c\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x08\x05\x61\
    \x64\x6d\x69\x6e\xc0\x0c";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(8, 9));
}

#[test]
fn minfo_example_org_response_3() {
    let msg = b"\x03\x10\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0e\x00\x01\xc0\x0c\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x11\x05\x61\
    \x64\x6d\x69\x6e\xc0\x0c\x05\x65\x72\x72\x6f\x72\xc0\x0c\x00";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(17, 16));
}

#[test]
fn sshfp_example_org_response_1() {
    let msg = b"\xe4\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2c\x00\x01\xc0\x0c\x00\x2c\x00\x01\x00\x00\x0e\x10\x00\x16\x03\x01\
    \x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90";
    decode_msg_error(&msg[..], DecodeError::SSHFPAlgorithm(3));
}

#[test]
fn sshfp_example_org_response_2() {
    let msg = b"\xe4\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2c\x00\x01\xc0\x0c\x00\x2c\x00\x01\x00\x00\x0e\x10\x00\x16\x02\x02\
    \x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90";
    decode_msg_error(&msg[..], DecodeError::SSHFPType(2));
}

#[test]
fn sshfp_example_org_response_3() {
    let msg = b"\xe4\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2c\x00\x01\xc0\x0c\x00\x2c\x00\x01\x00\x00\x0e\x10\x00\x16\x02\x01\
    \x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(62, 63));
}

#[test]
fn aaaa_example_org_response() {
    let msg = b"\xeb\xac\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x04\x00\x00\x0e\x10\x00\x10\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    decode_msg_error(&msg[..], DecodeError::AAAAClass(Class::HS));
}

#[test]
fn eui48_example_org_request_1() {
    let msg = b"\xda\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6c\x00\x01\xc0\x0c\x00\x6c\x00\x01\x00\x00\x0e\x10\x00\x07\x00\x11\
    \x22\x33\x44\x55\x66";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(7, 6));
}

#[test]
fn eui48_example_org_request_2() {
    let msg = b"\xda\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6c\x00\x01\xc0\x0c\x00\x6c\x00\x01\x00\x00\x0e\x10\x00\x05\x00\x11\
    \x22\x33\x44";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(5, 6));
}

#[test]
fn eui64_example_org_request_1() {
    let msg = b"\x43\xb0\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6d\x00\x01\xc0\x0c\x00\x6d\x00\x01\x00\x00\x0e\x10\x00\x09\x00\x11\
    \x22\x33\x44\x55\x66\x77\x88";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(9, 8));
}

#[test]
fn eui64_example_org_request_2() {
    let msg = b"\x43\xb0\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6d\x00\x01\xc0\x0c\x00\x6d\x00\x01\x00\x00\x0e\x10\x00\x07\x00\x11\
    \x22\x33\x44\x55\x66";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(7, 8));
}

#[test]
fn nid_example_org_request_1() {
    let msg = b"\x6c\xbc\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x68\x00\x01\xc0\x0c\x00\x68\x00\x01\x00\x00\x0e\x10\x00\x09\x00\x0a\
    \xff\xee\xdd\xcc\xbb\xaa\x99";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(9, 10));
}

#[test]
fn nid_example_org_request_2() {
    let msg = b"\x6c\xbc\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x68\x00\x01\xc0\x0c\x00\x68\x00\x01\x00\x00\x0e\x10\x00\x0b\x00\x0a\
    \xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(11, 10));
}

#[test]
fn l32_example_org_request_1() {
    let msg = b"\xe9\x14\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x69\x00\x01\xc0\x0c\x00\x69\x00\x01\x00\x00\x0e\x10\x00\x05\x00\x0a\
    \x0a\x00\x00";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(5, 6));
}

#[test]
fn l32_example_org_request_2() {
    let msg = b"\xe9\x14\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x69\x00\x01\xc0\x0c\x00\x69\x00\x01\x00\x00\x0e\x10\x00\x07\x00\x0a\
    \x0a\x00\x00\x01\xff";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(7, 6));
}

#[test]
fn l64_example_org_request_1() {
    let msg = b"\xca\xa7\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6a\x00\x01\xc0\x0c\x00\x6a\x00\x01\x00\x00\x0e\x10\x00\x09\x00\x0a\
    \x20\x21\x22\x23\x24\x25\x26";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(9, 10));
}

#[test]
fn l64_example_org_request_2() {
    let msg = b"\xca\xa7\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6a\x00\x01\xc0\x0c\x00\x6a\x00\x01\x00\x00\x0e\x10\x00\x0b\x00\x0a\
    \x20\x21\x22\x23\x24\x25\x26\x27\x28";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(11, 10));
}

#[test]
fn lp_example_org_request_1() {
    let msg = b"\x76\x46\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6b\x00\x01\xc0\x0c\x00\x6b\x00\x01\x00\x00\x0e\x10\x00\x19\x00\x0a\
    \x0a\x6c\x36\x34\x2d\x73\x75\x62\x6e\x65\x74\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(25, 26));
}

#[test]
fn lp_example_org_request_2() {
    let msg = b"\x76\x46\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6b\x00\x01\xc0\x0c\x00\x6b\x00\x01\x00\x00\x0e\x10\x00\x1b\x00\x0a\
    \x0a\x6c\x36\x34\x2d\x73\x75\x62\x6e\x65\x74\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\
    \x00\xff";
    decode_msg_error(&msg[..], DecodeError::TooManyBytes(27, 26));
}

#[test]
fn uri_example_ort_response_1() {
    let msg = b"\xec\x64\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04\x5f\x66\x74\x70\x04\x5f\x74\
    \x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x01\x00\x00\x01\xc0\x0c\x01\x00\
    \x00\x01\x00\x00\x0e\x10\x00\x02\x00\x0a";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(2, 4));
}

#[test]
fn uri_example_ort_response_2() {
    let msg = b"\xec\x64\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04\x5f\x66\x74\x70\x04\x5f\x74\
    \x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x01\x00\x00\x01\xc0\x0c\x01\x00\
    \x00\x01\x00\x00\x0e\x10\x00\x1a\x00\x0a\x00\x01\x66\x74\x70\x3a\x2f\x2f\x66\x74\x70\x2e\x65\
    \x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67";
    decode_msg_error(&msg[..], DecodeError::NotEnoughBytes(76, 77));
}

#[test]
fn opt_ecs_example_org_request_1() {
    let msg = b"\x46\xfd\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\
    \x07\x00\x01\xff\x00\x0a\x00\x00";
    decode_msg_error(
        &msg[..],
        DecodeError::AddressError(AddressError::Ipv4Prefix(255)),
    );
}

#[test]
fn opt_ecs_example_org_request_2() {
    let msg = b"\x46\xfd\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\
    \x07\x00\x01\x00\x00\x0a\x00\x00";
    decode_msg_error(
        &msg[..],
        DecodeError::AddressError(AddressError::Ipv4Mask("10.0.0.0".parse().unwrap(), 0)),
    );
}

#[test]
fn opt_ecs_example_org_request_3() {
    let msg = b"\x7d\x2a\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x10\x00\x08\x00\
    \x0c\x00\x02\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    decode_msg_error(
        &msg[..],
        DecodeError::AddressError(AddressError::Ipv6Prefix(255)),
    );
}

#[test]
fn opt_ecs_example_org_request_4() {
    let msg = b"\x7d\x2a\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x10\x00\x08\x00\
    \x0c\x00\x02\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00";
    decode_msg_error(
        &msg[..],
        DecodeError::AddressError(AddressError::Ipv6Mask("a00::".parse().unwrap(), 0)),
    );
}

#[test]
fn opt_ecs_example_org_response_5() {
    let msg = b"\x46\xfd\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\x07\x00\x03\x18\x00\x0a\x00\
    \x00";
    decode_msg_error(&msg[..], DecodeError::EcsAddressNumber(3));
}

#[test]
fn opt_ecs_example_org_response_6() {
    let msg = b"\x46\xfd\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0d\x00\x08\x00\x09\x00\x01\x18\x00\x0a\x00\
    \x00\x00\x00";
    decode_msg_error(&msg[..], DecodeError::EcsTooBigIpv4Address(5));
}

#[test]
fn opt_ecs_example_org_response_7() {
    let msg = b"\x7d\x2a\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x19\x00\x08\x00\x15\x00\x02\x40\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    decode_msg_error(&msg[..], DecodeError::EcsTooBigIpv6Address(17));
}

#[test]
fn opt_cookie_example_org_request() {
    let msg = b"\x46\x53\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0d\x00\x0a\x00\
    \x09\xd5\xa7\xe3\x00\x4d\x79\x05\x1e\xff";
    decode_msg_error(&msg[..], DecodeError::CookieLength(9));
}

#[test]
fn opt_cookie_example_org_response() {
    let msg = b"\x46\x53\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x2d\x00\x0a\x00\x29\xd5\xa7\xe3\x00\x4d\x79\
    \x05\x1e\x01\x00\x00\x00\x5f\xe5\xd6\xb1\x62\xda\x1b\xe3\xbc\x92\x5b\xd6\x01\x02\x03\x04\x05\
    \x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11";
    decode_msg_error(&msg[..], DecodeError::CookieLength(41));
}

#[test]
fn apl_example_org_response() {
    let msg = b"\x75\xc4\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2a\x00\x01\xc0\x0c\x00\x2a\x00\x03\x00\x00\x0e\x10\x00\x0a\x00\x01\
    \x10\x01\x0a\x00\x01\x10\x01\x14";
    decode_msg_error(&msg[..], DecodeError::APLClass(Class::CH));
}
