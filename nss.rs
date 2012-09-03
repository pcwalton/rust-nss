//
// General NSS bindings.
//
// Copyright (c) 2012 Mozilla Foundation
//

use common::{NSSResult, SECStatus, ToResult};

use libc::c_char;
use result::Result;

fn init(configdir: &str) -> NSSResult {
    do str::as_c_str(configdir) |configdir| {
        NSS_Init(configdir).to_result()
    }
}

fn init_nodb(configdir: &str) -> NSSResult {
    do str::as_c_str(configdir) |configdir| {
        NSS_NoDB_Init(configdir).to_result()
    }
}

#[link_name="nss3"]
extern {
    fn NSS_Init(configdir: *c_char) -> SECStatus;
    fn NSS_NoDB_Init(configdir: *c_char) -> SECStatus;
}

