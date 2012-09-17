//
// rust-nss/pk11pub.rs
//
// Cryptographic primitives.
//
// Copyright (c) 2012 Mozilla Foundation
//

use common::{Item, NSSResult, SECItem, ToResult};
use nsprpub::PRBool;
use pkcs11t::{CKAttributeType, CKMechanismType, CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE};
use secmodt::PK11Origin;

use libc::{c_uchar, c_uint, c_void};
use ptr::{null, to_mut_unsafe_ptr, to_unsafe_ptr};
use result::{Err, Ok, Result};
use vec::raw::to_ptr;

// Slot mapping utility functions

struct PK11SlotInfo { priv private: () }

struct SlotInfo {
    obj: *PK11SlotInfo,

    drop {
        PK11_FreeSlot(self.obj);
    }
}

mod SlotInfo {
    fn wrap(obj: *PK11SlotInfo) -> SlotInfo {
        SlotInfo { obj: obj }
    }

    fn best(ty: CKMechanismType) -> SlotInfo {
        SlotInfo::wrap(PK11_GetBestSlot(ty, null()))
    }
}

// Symmetric, public, and private keys

struct PK11SymKey { priv private: () }

struct SymKey {
    obj: *PK11SymKey,

    drop {
        PK11_FreeSymKey(self.obj);
    }
}

mod SymKey {
    fn wrap(obj: *PK11SymKey) -> SymKey {
        SymKey { obj: obj }
    }
}

impl SlotInfo {
    fn import_sym_key(&self, ty: CKMechanismType, origin: PK11Origin, operation: CKAttributeType,
                      key: &Item)
                   -> SymKey {
        SymKey::wrap(PK11_ImportSymKey(self.obj, ty, origin, operation,
                                       to_unsafe_ptr(&key.unwrap()), null()))
    }
}

// Crypto contexts

struct PK11Context { priv private: () }

struct Context {
    obj: *PK11Context,

    drop {
        PK11_DestroyContext(self.obj, true as PRBool);
    }
}

mod Context {
    fn wrap(obj: *PK11Context) -> Context {
        Context { obj: obj }
    }

    fn new_with_sym_key(ty: CKMechanismType, operation: CKAttributeType, sym_key: &SymKey,
                        param: &mut Item)
                     -> Context {
		unsafe {
			let cx = PK11_CreateContextBySymKey(ty, operation, sym_key.obj,
												to_unsafe_ptr(&param.unwrap()));
			Context::wrap(cx)
		}
    }
}

impl Context {
    fn digest_begin(&self) -> NSSResult {
        PK11_DigestBegin(self.obj).to_result()
    }

    fn digest_op(&self, data: &[u8]) -> NSSResult {
        unsafe {
            PK11_DigestOp(self.obj, to_ptr(data), data.len() as c_uint).to_result()
        }
    }

    fn digest_final(&self) -> Result<~[u8],()> {
        unsafe {
            let mut bytes = vec::from_elem(32, 0);
            let mut length = 0;
            let orig_length = bytes.len() as c_uint;
            let status = PK11_DigestFinal(self.obj,
                                          to_ptr(bytes),
                                          to_mut_unsafe_ptr(&mut length),
                                          to_unsafe_ptr(&orig_length));
            if status > 0 { return Err(()); }
            vec::truncate(bytes, length as uint);
            return Ok(move bytes);
        }
    }
}

#[link_name="nss3"]
extern {
    // Slot mapping utility functions
    fn PK11_GetBestSlot(ty: CK_MECHANISM_TYPE, wincx: *c_void) -> *PK11SlotInfo;

    // Generic slot management
    fn PK11_FreeSlot(slot: *PK11SlotInfo);

    // Symmetric, public, and private keys
    fn PK11_FreeSymKey(key: *PK11SymKey);
    fn PK11_ImportSymKey(slot: *PK11SlotInfo, ty: CK_MECHANISM_TYPE, origin: PK11Origin,
                         operation: CK_ATTRIBUTE_TYPE, key: *SECItem, wincx: *c_void)
                      -> *PK11SymKey;

    // Crypto contexts
    fn PK11_DestroyContext(context: *PK11Context, freeit: PRBool);
    fn PK11_CreateContextBySymKey(ty: CK_MECHANISM_TYPE, operation: CK_ATTRIBUTE_TYPE,
                                  symKey: *PK11SymKey, param: *SECItem)
                               -> *PK11Context;
    fn PK11_DigestBegin(cx: *PK11Context) -> SECStatus;
    fn PK11_DigestOp(context: *PK11Context, in: *u8, len: c_uint) -> SECStatus;
    fn PK11_DigestFinal(context: *PK11Context, data: *c_uchar, outLen: *mut c_uint,
                        length: *c_uint)
                     -> SECStatus;
}

