// SPDX-License-Identifier: Apache-2.0

//! This crate provides the Enarx client
//!
//! # Build
//!
//!     $ git clone https://github.com/enarx/enarx
//!     $ cd enarx
//!     $ cargo build
//!

#![deny(clippy::all)]
extern crate reqwest;
extern crate serde_derive;

use koine::*;

//use serde_derive::{Deserialize, Serialize};
//use reqwest::Body;
use serde_cbor::{from_slice, to_vec};
//use std::collections::HashMap;
//use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//use uuid::Uuid;
/*
pub const KEEP_ARCH_NIL: &str = "nil";

//TODO - move to shared library
#[derive(Serialize, Deserialize, Clone)]
pub struct KeepMgr {
    pub ipaddr: String,
    pub port: u16,
}

//TODO - move to shared library
#[derive(Serialize, Deserialize, Clone)]
pub struct KeepContract {
    pub keepmgr: KeepMgr,
    pub backend: String,
    //TODO - add duration of contract availability
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Wasmldr {
    pub wasmldr_ipaddr: String,
    pub wasmldr_port: u16,
}

//TODO - move to shread library?
#[derive(Serialize, Deserialize, Clone)]
pub struct Keep {
    pub keepmgr: KeepMgr,
    pub backend: String,
    pub kuuid: Uuid,
    pub state: String,
    pub wasmldr: Option<Wasmldr>,
    pub human_readable_info: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeepLoader {
    pub state: u8,
    pub kuuid: Uuid,
    pub app_loader_bind_port: u16,
    pub bindaddress: String,
    pub backend: String,
    //we may wish to add information here about whether we're happy to share
    // all of this information with external parties, but since the keeploader
    // is operating outside the TEE boundary, there's only so much we can do
    // to keep this information confidential
}

pub struct Workload {
    pub wasm_binary: Vec<u8>,
    pub human_readable_info: String,
}
*/

//currently only one Keep-Manager and one Keep supported
fn main() {
    //list available keepmgrs
    // - currently only localhost supported

    //for a particular keepmgr, list available keep_types
    // (actually contracts)
    //  - test with "Nil"
    let keepmgr = KeepMgr {
        ipaddr: String::from("127.0.0.1"),
        port: 3030,
        keeps: Vec::new(),
    };
    let keepcontract = KeepContract {
        keepmgr: keepmgr.clone(),
        backend: Backend::Nil,
    };
    //create keep
    let _keep_result = new_keep(&keepmgr, &keepcontract);
    //perform attestation
    //steps required will depend on backend

    //get certificate from keepldr
    //get address & port
    //STATE: keep ready for us to connect to it

    //disconnect from keepmgr

    //choose wasm workload

    //connect to keepldr via HTTPS
    // (note validate server against certificate received above)

    //send wasm workload
}

pub fn list_hosts() -> Result<Vec<KeepMgr>, String> {
    Err("Unimplemented".to_string())
}

//TODO - create Keep struct, including backend, what else?
pub fn list_keepcontracts(_keepmgr: &KeepMgr) -> Result<Vec<KeepContract>, String> {
    Err("Unimplemented".to_string())
}

pub fn new_keep(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Keep, String> {
    //TODO - cbor pass new-keep command
    let mime_new_keep = MIMENewKeep {
        //NOTE - auth_token not currently used
        //FIXME - remove for now
        auth_token: String::from(""),
        keepcontract: keepcontract.clone(),
    };
    let cbor_msg = to_vec(&mime_new_keep);
    /*
    let mut command_new_keep: HashMap<String, String> = HashMap::new();
    command_new_keep.insert("command".to_string(), "new-keep".to_string());
    //    command_new_keep.insert("keep-arch".to_string(), KEEP_ARCH_NIL.to_string());
    command_new_keep.insert("auth-token".to_string(), "a3f9cb07".to_string());
     */
    let keep_mgr_url = format!("https://{}:{}/keeps_post/", keepmgr.ipaddr, keepmgr.port);

    let response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg.unwrap())
        .send()
        .expect("Problem starting keep");

    //FIXME - we actually get a KeepLoader from this...
    //let keep: Keep = response.json().expect("TODO - error handling");
    let keep = from_slice(&response.bytes().unwrap()).unwrap();
    Ok(keep)
}

pub fn attest_keep(_keep: &Keep) -> Result<bool, String> {
    Err("Unimplemented".to_string())
}

pub fn get_keep_wasmldr_info(_keep: &Keep) -> Result<Wasmldr, String> {
    Err("Unimplemented".to_string())
}

pub fn provision_workload(_keep: &Keep, _workload: &Workload) -> Result<bool, String> {
    Err("Unimplemented".to_string())
}
