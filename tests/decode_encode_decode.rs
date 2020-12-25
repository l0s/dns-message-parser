use bytes::Bytes;
use dns_message_parser::{Dns, Flags, Opcode, RCode};

fn decode_msg(msg: &[u8]) -> Dns {
    // Decode BytesMut to message
    let bytes = Bytes::copy_from_slice(&msg[..]);
    // Decode the DNS message
    Dns::decode(bytes).unwrap()
}

fn decode_encode_decode(msg: &[u8]) {
    let dns_1 = decode_msg(msg);
    // Check the result
    let bytes = dns_1.encode().unwrap();
    let dns_2 = decode_msg(bytes.as_ref());
    // Check if is equal
    assert_eq!(dns_1, dns_2);
}

#[test]
fn flags() {
    let flags_1 = Flags {
        qr: true,
        opcode: Opcode::Query,
        aa: true,
        tc: true,
        rd: true,
        ra: true,
        ad: true,
        cd: true,
        rcode: RCode::NoError,
    };

    let bytes = flags_1.encode();
    let flags_2 = Flags::decode(bytes.freeze()).unwrap();
    assert_eq!(flags_1, flags_2);
}

#[test]
fn empty_request() {
    let msg = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn a_example_org_request() {
    let msg = b"\xdb\x1c\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn a_example_org_response() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";
    decode_encode_decode(&msg[..]);
}

#[test]
fn ns_example_org_request() {
    let msg = b"\x03\x78\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x02\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn ns_example_org_response() {
    let msg = b"\x03\x78\x85\x80\x00\x01\x00\x02\x00\x00\x00\x02\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x00\x0e\x10\x00\x06\x03\x6e\
    \x73\x31\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x00\x0e\x10\x00\x06\x03\x6e\x73\x32\xc0\x0c\xc0\
    \x29\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01\xc0\x3b\x00\x01\x00\x01\x00\x00\
    \x0e\x10\x00\x04\x0a\x00\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn cname_example_org_request() {
    let msg = b"\xe2\x7b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x05\x63\x6e\x61\x6d\x65\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x05\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn cname_example_org_response() {
    let msg = b"\xe2\x7b\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05\x63\x6e\x61\x6d\x65\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\
    \x0e\x10\x00\x02\xc0\x12";
    decode_encode_decode(&msg[..]);
}

#[test]
fn soa_example_org_request() {
    let msg = b"\xeb\x9c\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x06\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn soa_example_org_response() {
    let msg = b"\xeb\x9c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x22\x03\x6e\
    \x73\x31\xc0\x0c\x05\x61\x64\x6d\x69\x6e\xc0\x0c\x00\x00\x00\x01\x00\x00\x2a\x30\x00\x00\x0e\
    \x10\x00\x09\x3a\x80\x00\x00\x0e\x10";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mb_example_org_request() {
    let msg = b"\x36\x8b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x07\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mb_example_org_response() {
    let msg = b"\x36\x8b\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x07\x00\x01\xc0\x0c\x00\x07\x00\x01\x00\x00\x0e\x10\x00\x07\x04\x6d\
    \x61\x69\x6c\xc0\x0c\xc0\x29\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0c";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mg_example_org_request() {
    let msg = b"\x7d\x35\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x08\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mg_example_org_response() {
    let msg = b"\x7d\x35\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x08\x00\x01\xc0\x0c\x00\x08\x00\x01\x00\x00\x0e\x10\x00\x07\x04\x6d\
    \x61\x69\x6c\xc0\x0c";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mr_example_org_request() {
    let msg = b"\xa3\xc4\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x09\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mr_example_org_response() {
    let msg = b"\xa3\xc4\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x09\x00\x01\xc0\x0c\x00\x09\x00\x01\x00\x00\x0e\x10\x00\x07\x04\x6d\
    \x61\x69\x6c\xc0\x0c";
    decode_encode_decode(&msg[..]);
}

#[test]
fn wks_example_org_request() {
    let msg = b"\xd9\xc6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0b\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn wks_example_org_response() {
    let msg = b"\xd9\xc6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0b\x00\x01\xc0\x0c\x00\x0b\x00\x01\x00\x00\x0e\x10\x00\x08\x0a\x00\
    \x00\x0a\x06\x01\x00\x15";
    decode_encode_decode(&msg[..]);
}

#[test]
fn ptr_example_org_request() {
    let msg = b"\x0c\x72\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x02\x31\x30\x01\x30\x01\x30\x02\
    \x31\x30\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x0c\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn ptr_example_org_response() {
    let msg = b"\x0c\x72\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x02\x31\x30\x01\x30\x01\x30\x02\
    \x31\x30\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\
    \x00\x01\x00\x00\x0e\x10\x00\x0d\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn hinfo_example_org_request() {
    let msg = b"\x78\x99\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0d\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn hinfo_example_org_response() {
    let msg = b"\x78\x99\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0d\x00\x01\xc0\x0c\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x0b\x04\x54\
    \x45\x53\x54\x05\x4c\x69\x6e\x75\x78";
    decode_encode_decode(&msg[..]);
}

#[test]
fn minfo_example_org_request() {
    let msg = b"\x03\x10\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0e\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn minfo_example_org_response() {
    let msg = b"\x03\x10\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0e\x00\x01\xc0\x0c\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x10\x05\x61\
    \x64\x6d\x69\x6e\xc0\x0c\x05\x65\x72\x72\x6f\x72\xc0\x0c";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mx_example_org_request() {
    let msg = b"\xca\x2d\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0f\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn mx_example_org_response() {
    let msg = b"\xca\x2d\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\x00\x00\x0e\x10\x00\x09\x00\x0a\
    \x04\x6d\x61\x69\x6c\xc0\x0c\xc0\x2b\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0c";
    decode_encode_decode(&msg[..]);
}

#[test]
fn txt_example_org_request() {
    let msg = b"\x25\xd6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x10\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn txt_example_org_response() {
    let msg = b"\x25\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x0e\x10\x00\x05\x04\x54\
    \x65\x78\x74";
    decode_encode_decode(&msg[..]);
}

#[test]
fn rp_example_org_request() {
    let msg = b"\x9b\xf1\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x11\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn rp_example_org_response() {
    let msg = b"\x9b\xf1\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x11\x00\x01\xc0\x0c\x00\x11\x00\x01\x00\x00\x0e\x10\x00\x20\x05\x61\
    \x64\x6d\x69\x6e\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x07\x65\x78\x61\x6d\x70\
    \x6c\x65\x03\x6f\x72\x67\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn afsdb_example_org_request() {
    let msg = b"\x10\x2b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x12\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn afsdb_example_org_response() {
    let msg = b"\x10\x2b\x85\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x12\x00\x01\xc0\x0c\x00\x12\x00\x01\x00\x00\x0e\x10\x00\x15\x00\x01\
    \x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x0c\x00\x12\
    \x00\x01\x00\x00\x0e\x10\x00\x15\x00\x02\x05\x61\x66\x73\x64\x62\x07\x65\x78\x61\x6d\x70\x6c\
    \x65\x03\x6f\x72\x67\x00\xc0\x4c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x0e";
    decode_encode_decode(&msg[..]);
}

#[test]
fn x25_example_org_request() {
    let msg = b"\x51\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x05\x72\x65\x6c\x61\x79\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x13\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn x25_example_org_response() {
    let msg = b"\x51\x00\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05\x72\x65\x6c\x61\x79\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x13\x00\x01\xc0\x0c\x00\x13\x00\x01\x00\x00\
    \x0e\x10\x00\x0d\x0c\x33\x31\x31\x30\x36\x31\x37\x30\x30\x39\x35\x36";
    decode_encode_decode(&msg[..]);
}

#[test]
fn isdn_example_org_request() {
    let msg = b"\x4f\xb2\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x05\x72\x65\x6c\x61\x79\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x14\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn isdn_example_org_response() {
    let msg = b"\x4f\xb2\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05\x72\x65\x6c\x61\x79\x07\x65\
    \x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x14\x00\x01\xc0\x0c\x00\x14\x00\x01\x00\x00\
    \x0e\x10\x00\x14\x0f\x31\x35\x30\x38\x36\x32\x30\x32\x38\x30\x30\x33\x32\x31\x37\x03\x30\x30\
    \x34";
    decode_encode_decode(&msg[..]);
}

#[test]
fn rt_example_org_request() {
    let msg = b"\x05\xa4\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x15\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn rt_example_org_response() {
    let msg = b"\x05\xa4\x85\x80\x00\x01\x00\x01\x00\x00\x00\x03\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x15\x00\x01\xc0\x0c\x00\x15\x00\x01\x00\x00\x0e\x10\x00\x15\x00\x02\
    \x05\x72\x65\x6c\x61\x79\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x2b\x00\x01\
    \x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\x00\x10\xc0\x2b\x00\x13\x00\x01\x00\x00\x0e\x10\x00\
    \x0d\x0c\x33\x31\x31\x30\x36\x31\x37\x30\x30\x39\x35\x36\xc0\x2b\x00\x14\x00\x01\x00\x00\x0e\
    \x10\x00\x14\x0f\x31\x35\x30\x38\x36\x32\x30\x32\x38\x30\x30\x33\x32\x31\x37\x03\x30\x30\x34";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nsap_example_org_request() {
    let msg = b"\x13\x86\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x04\x6e\x73\x61\x70\x07\x65\x78\
    \x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x16\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nsap_example_org_response() {
    let msg = b"\x13\x86\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04\x6e\x73\x61\x70\x07\x65\x78\
    \x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x16\x00\x01\xc0\x0c\x00\x16\x00\x01\x00\x00\x0e\
    \x10\x00\x14\x47\x00\x05\x80\x00\x5a\x00\x00\x00\x00\x01\xe1\x33\xff\xff\xff\x00\x01\x61\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn px_example_org_request() {
    let msg = b"\xda\xbb\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x02\x70\x78\x07\x65\x78\x61\x6d\
    \x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1a\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn px_example_org_response() {
    let msg = b"\xda\xbb\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x02\x70\x78\x07\x65\x78\x61\x6d\
    \x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1a\x00\x01\xc0\x0c\x00\x1a\x00\x01\x00\x00\x0e\x10\x00\
    \x22\x00\x0a\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x05\x70\x78\x34\x30\x30\x07\
    \x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn gpos_example_org_request() {
    let msg = b"\x98\x89\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1b\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn gpos_example_org_response() {
    let msg = b"\x98\x89\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1b\x00\x01\xc0\x0c\x00\x1b\x00\x01\x00\x00\x0e\x10\x00\x17\x08\x2d\
    \x33\x32\x2e\x30\x30\x38\x32\x08\x31\x32\x30\x2e\x30\x30\x35\x30\x04\x31\x30\x2e\x30";
    decode_encode_decode(&msg[..]);
}

#[test]
fn aaaa_example_org_request() {
    let msg = b"\xeb\xac\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1c\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn aaaa_example_org_response() {
    let msg = b"\xeb\xac\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn loc_example_org_request() {
    let msg = b"\xf6\x5e\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1d\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn loc_example_org_response() {
    let msg = b"\xf6\x5e\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1d\x00\x01\xc0\x0c\x00\x1d\x00\x01\x00\x00\x0e\x10\x00\x10\x00\x33\
    \x16\x13\x89\xd1\xe2\xb0\x70\xfa\x7a\xe0\x00\x98\x8e\xb0";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eid_example_org_request() {
    let msg = b"\x93\xe3\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1f\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eid_example_org_response() {
    let msg = b"\x93\xe3\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x1f\x00\x01\xc0\x0c\x00\x1f\x00\x01\x00\x00\x0e\x10\x00\x08\xe3\x2c\
    \x6f\x78\x16\x3a\x93\x48";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nimloc_example_org_request() {
    let msg = b"\x6b\xb3\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x20\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nimloc_example_org_response() {
    let msg = b"\x6b\xb3\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x20\x00\x01\xc0\x0c\x00\x20\x00\x01\x00\x00\x0e\x10\x00\x06\x32\x25\
    \x1a\x03\x00\x67";
    decode_encode_decode(&msg[..]);
}

#[test]
fn srv_example_org_request() {
    let msg = b"\x9f\xed\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x05\x5f\x68\x74\x74\x70\x04\x5f\
    \x74\x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x21\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn srv_example_org_response() {
    let msg = b"\x9f\xed\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x05\x5f\x68\x74\x74\x70\x04\x5f\
    \x74\x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x21\x00\x01\xc0\x0c\x00\
    \x21\x00\x01\x00\x00\x0e\x10\x00\x17\x00\x00\x00\x01\x00\x50\x03\x73\x72\x76\x07\x65\x78\x61\
    \x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x3a\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x18";
    decode_encode_decode(&msg[..]);
}

#[test]
fn kx_example_org_request() {
    let msg = b"\xca\x1b\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x24\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn kx_example_org_response() {
    let msg = b"\xca\x1b\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x24\x00\x01\xc0\x0c\x00\x24\x00\x01\x00\x00\x0e\x10\x00\x12\x00\x0a\
    \x02\x6b\x78\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\xc0\x2b\x00\x01\x00\x01\x00\
    \x00\x0e\x10\x00\x04\x0a\x00\x00\x1a";
    decode_encode_decode(&msg[..]);
}

#[test]
fn dname_example_org_request() {
    let msg = b"\xd9\xd6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x03\x6e\x73\x31\x07\x65\x78\x61\
    \x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x27\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn dname_example_org_response() {
    let msg = b"\xd9\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03\x6e\x73\x31\x07\x65\x78\x61\
    \x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x27\x00\x01\xc0\x0c\x00\x27\x00\x01\x00\x00\x0e\x10\
    \x00\x13\x05\x64\x6e\x61\x6d\x65\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn sshfp_example_org_request() {
    let msg = b"\xe4\xd6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2c\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn sshfp_example_org_response() {
    let msg = b"\xe4\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x2c\x00\x01\xc0\x0c\x00\x2c\x00\x01\x00\x00\x0e\x10\x00\x16\x02\x01\
    \x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nid_example_org_response() {
    let msg = b"\x6c\xbc\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x68\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn nid_example_org_request() {
    let msg = b"\x6c\xbc\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x68\x00\x01\xc0\x0c\x00\x68\x00\x01\x00\x00\x0e\x10\x00\x0a\x00\x0a\
    \xff\xee\xdd\xcc\xbb\xaa\x99\x88";
    decode_encode_decode(&msg[..]);
}

#[test]
fn l32_example_org_response() {
    let msg = b"\xe9\x14\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x69\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn l32_example_org_request() {
    let msg = b"\xe9\x14\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x69\x00\x01\xc0\x0c\x00\x69\x00\x01\x00\x00\x0e\x10\x00\x06\x00\x0a\
    \x0a\x00\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn l64_example_org_response() {
    let msg = b"\xca\xa7\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6a\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn l64_example_org_request() {
    let msg = b"\xca\xa7\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6a\x00\x01\xc0\x0c\x00\x6a\x00\x01\x00\x00\x0e\x10\x00\x0a\x00\x0a\
    \x20\x21\x22\x23\x24\x25\x26\x27";
    decode_encode_decode(&msg[..]);
}

#[test]
fn lp_example_org_response() {
    let msg = b"\x76\x46\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6b\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn lp_example_org_request() {
    let msg = b"\x76\x46\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6b\x00\x01\xc0\x0c\x00\x6b\x00\x01\x00\x00\x0e\x10\x00\x1a\x00\x0a\
    \x0a\x6c\x36\x34\x2d\x73\x75\x62\x6e\x65\x74\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\
    \x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eui48_example_org_response() {
    let msg = b"\xda\xd6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6c\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eui48_example_org_request() {
    let msg = b"\xda\xd6\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6c\x00\x01\xc0\x0c\x00\x6c\x00\x01\x00\x00\x0e\x10\x00\x06\x00\x11\
    \x22\x33\x44\x55";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eui64_example_org_response() {
    let msg = b"\x43\xb0\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6d\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn eui64_example_org_request() {
    let msg = b"\x43\xb0\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x6d\x00\x01\xc0\x0c\x00\x6d\x00\x01\x00\x00\x0e\x10\x00\x08\x00\x11\
    \x22\x33\x44\x55\x66\x77";
    decode_encode_decode(&msg[..]);
}

#[test]
fn uri_example_org_request() {
    let msg = b"\xec\x64\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x04\x5f\x66\x74\x70\x04\x5f\x74\
    \x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x01\x00\x00\x01";
    decode_encode_decode(&msg[..]);
}

#[test]
fn uri_example_org_response() {
    let msg = b"\xec\x64\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04\x5f\x66\x74\x70\x04\x5f\x74\
    \x63\x70\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x01\x00\x00\x01\xc0\x0c\x01\x00\
    \x00\x01\x00\x00\x0e\x10\x00\x1a\x00\x0a\x00\x01\x66\x74\x70\x3a\x2f\x2f\x66\x74\x70\x2e\x65\
    \x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x2f";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_ecs_example_org_request_1() {
    let msg = b"\x46\xfd\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\
    \x07\x00\x01\x18\x00\x0a\x00\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_ecs_example_org_response_1() {
    let msg = b"\x46\xfd\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\x07\x00\x01\x18\x00\x0a\x00\
    \x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_ecs_example_org_request_2() {
    let msg = b"\x7d\x2a\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x10\x00\x08\x00\
    \x0c\x00\x02\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_ecs_example_org_response_2() {
    let msg = b"\x7d\x2a\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x10\x00\x08\x00\x0c\x00\x02\x40\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_cookie_example_org_request() {
    let msg = b"\x46\x53\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\
    \x08\xd5\xa7\xe3\x00\x4d\x79\x05\x1e";
    decode_encode_decode(&msg[..]);
}

#[test]
fn opt_cookie_example_org_response() {
    let msg = b"\x46\x53\x85\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x1c\x00\x0a\x00\x18\xd5\xa7\xe3\x00\x4d\x79\
    \x05\x1e\x01\x00\x00\x00\x5f\xe5\xd6\xb1\x62\xda\x1b\xe3\xbc\x92\x5b\xd6";
    decode_encode_decode(&msg[..]);
}
