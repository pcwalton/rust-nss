//
// rust-nss/nsprpub.h
//
// Public NSPR types.
// FIXME: This should really be part of a rust-nspr library instead.
//
// Copyright (c) 2012 Mozilla Foundation
//

use libc::c_int;

type PRIntn = c_int;

type PRBool = PRIntn;
const PR_TRUE: PRBool = 1;
const PR_FALSE: PRBool = 0;

