//
// rust-nss/secmodt.rs
//
// Miscellaneous security types.
//
// Copyright (c) 2012 Mozilla Foundation
//

use libc::c_int;

// FIXME: Botch as usual; needs to be a newtype'd struct, but I don't trust the alignment.
type PK11Origin = c_int;

const PK11_OriginNULL: PK11Origin = 0;
const PK11_OriginDerive: PK11Origin = 1;
const PK11_OriginGenerated: PK11Origin = 2;
const PK11_OriginFortezzaHack: PK11Origin = 3;
const PK11_OriginUnwrap: PK11Origin = 4;

