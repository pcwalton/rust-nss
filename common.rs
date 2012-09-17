use libc::{c_int, c_uchar, c_uint};
use result::{Result, Ok, Err};

// Security items

type SECItemType = c_int;

const siBuffer: SECItemType = 0;
const siClearDataBuffer: SECItemType = 1;
const siCipherDataBuffer: SECItemType = 2;
const siDERCertBuffer: SECItemType = 3;
const siEncodedCertBuffer: SECItemType = 4;
const siDERNameBuffer: SECItemType = 5;
const siEncodedNameBuffer: SECItemType = 6;
const siAsciiNameString: SECItemType = 7;
const siAsciiString: SECItemType = 8;
const siDEROID: SECItemType = 9;
const siUnsignedInteger: SECItemType = 10;
const siUTCTime: SECItemType = 11;
const siGeneralizedTime: SECItemType = 12;
const siVisibleString: SECItemType = 13;
const siUTF8String: SECItemType = 14;
const siBMPString: SECItemType = 15;

struct SECItemStr {
    sec_type: SECItemType,
    data: *c_uchar,
    len: c_uint
}

type SECItem = SECItemStr;

struct Item {
    sec_type: SECItemType,
    data: &[u8]
}

impl Item {
    unsafe fn unwrap(&const self) -> SECItem {
        SECItemStr {
            sec_type: self.sec_type,
            data: vec::raw::to_ptr(self.data),
            len: self.data.len() as c_uint
        }
    }
}

// Other common data types

type NSSResult = Result<(),()>;

type SECStatus = c_int;

trait ToResult {
    fn to_result(&self) -> NSSResult;
}

impl SECStatus : ToResult {
    fn to_result(&self) -> NSSResult {
        if *self == 0 { Ok(()) } else { Err(()) }
    }
}

