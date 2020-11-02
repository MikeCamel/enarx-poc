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

use koine::*;

//use serde_derive::{Deserialize, Serialize};
//use reqwest::Body;
use serde_cbor::{from_slice, to_vec};

//use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//use uuid::Uuid;

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
    let keep_result: Keep = new_keep(&keepmgr, &keepcontract).unwrap();
    println!(
        "Received keep, kuuid = {:?}, backend = {}",
        keep_result.kuuid,
        keep_result.backend.as_str()
    );
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
    let cbor_msg = to_vec(&keepcontract);
    let keep_mgr_url = format!("https://{}:{}/keeps_post/", keepmgr.ipaddr, keepmgr.port);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg.unwrap())
        .send()
        .expect("Problem starting keep");

    let keep = from_slice(&cbor_response.bytes().unwrap()).unwrap();
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
