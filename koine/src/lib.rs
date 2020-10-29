// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const LOCAL_LISTEN_ADDRESS: &str = "0.0.0.0";

pub const PROTO_VERSION: f32 = 0.1;
pub const PROTO_NAME: &str = "Enarx-Keep-Manager";
pub const BIND_PORT: u16 = 3030;

#[derive(Serialize, Deserialize, Clone)]
pub enum LoaderState {
    Indeterminate,
    Ready,
    Running,
    Shutdown,
    Error,
}
//these are initial values used in existing an PoC implementation,
// many are expected to be changed
pub const KEEP_INFO_COMMAND: &str = "keep-info";
pub const CONTRACT_COMMAND: &str = "command";
pub const KEEP_COMMAND: &str = "command";
pub const KEEP_AUTH: &str = "auth-token";
pub const KEEP_PORT: &str = "keep-port";
pub const KEEP_ADDR: &str = "keep-addr";
pub const KEEP_KUUID: &str = "kuuid";
pub const KEEP_ARCH: &str = "keep-arch";
pub const WASMLDR_BIND_PORT_CMD: &str = "wasmldr-bind-port";
pub const WASMLDR_ADDR_CMD: &str = "wasmldr-addr";

#[derive(Serialize, Deserialize, Clone)]
pub enum Backend {
    Nil,
    Sev,
    Sgx,
    Kvm,
}

impl Backend {
    pub fn as_str(&self) -> &'static str {
        match *self {
            Backend::Nil => "Nil",
            Backend::Sev => "Sev",
            Backend::Sgx => "Sgx",
            Backend::Kvm => "Kvm",
        }
    }
}

pub type KeepList = Arc<Mutex<Vec<Keep>>>;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeepMgr {
    pub ipaddr: String,
    pub port: u16,
    pub keeps: Vec<Keep>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeepContract {
    pub keepmgr: KeepMgr,
    pub backend: Backend,
    //TODO - add duration of contract availability
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Wasmldr {
    pub wasmldr_ipaddr: String,
    pub wasmldr_port: u16,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Keep {
    pub backend: Backend,
    pub kuuid: Uuid,
    pub state: LoaderState,
    pub wasmldr: Option<Wasmldr>,
    pub human_readable_info: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Workload {
    pub wasm_binary: Vec<u8>,
    pub human_readable_info: String,
}

//TODO - rename in favour of cbor, possibly remove
#[derive(Serialize, Deserialize, Clone)]
pub struct Command {
    pub commandtype: String,
    pub commandcontents: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeepVec {
    pub klvec: Vec<Keep>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UndefinedReply {
    pub text: String,
}

//--------------MIME work below

pub const MIME_TYPE_SUFFIX: &str = "application/vnd.enarx.att.sev+cbor; msg=";

#[derive(Serialize, Deserialize, Clone)]
pub struct MIMEMessage<T: MIMEPayload> {
    pub mimetype: String,
    pub payload: T,
}

pub trait MIMEPayload {
    //NOTE -  all struct implementing this trait
    // also need to derive cbor::Deserialize
    // and cbor::Serialize
    fn mime_type(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
