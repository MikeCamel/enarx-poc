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
use serde_cbor::{from_slice, to_vec};
use std::net::{IpAddr, Ipv4Addr};

//currently only one Keep-Manager and one Keep supported
fn main() {
    //list available keepmgrs
    // - currently only localhost supported
    let my_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let keepmgr = KeepMgr {
        ipaddr: my_addr,
        port: 3030,
    };
    //for a particular keepmgr, list available
    //  - test with "Nil"
    let keepcontracts: Vec<KeepContract> = list_contracts(&keepmgr).unwrap();
    for keepcontract in keepcontracts.iter() {
        println!(
            "Contract available for a {} Keep",
            keepcontract.backend.as_str(),
        );
    }

    //TODO - use one of the ones we've retrieved
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

pub fn list_contracts(keepmgr: &KeepMgr) -> Result<Vec<KeepContract>, String> {
    let keep_mgr_url = format!(
        "https://{}:{}/list-contracts/",
        keepmgr.ipaddr, keepmgr.port
    );
    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        //.body()
        .send()
        .expect("Problem starting keep");

    let contractvec_response = from_slice(&cbor_response.bytes().unwrap());
    match contractvec_response {
        Ok(kcvec) => Ok(kcvec),
        Err(e) => {
            println!("Problem with keep response {}", e);
            Err("Error with response".to_string())
        }
    }
}
/*
pub fn backend_test(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Backend, String> {
    //FIXME - this for testing ONLY!
    println!("About to send backend = {}", &keepcontract.backend.as_str());
    let cbor_msg = to_vec(&keepcontract.backend);
    let keep_mgr_url = format!("http://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg.unwrap())
        .send()
        .expect("Problem getting response");
    println!("Got some sort of response!");

    let backend_response = from_slice(&cbor_response.bytes().unwrap());
    match backend_response {
        Ok(backend) => Ok(backend),
        Err(e) => {
            println!("Problem with response {}", e);
            Err("Error with response".to_string())
        }
    }

    //    Ok(backend)
}
*/
pub fn new_keep(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Keep, String> {
    let cbor_msg = to_vec(&keepcontract);
    let keep_mgr_url = format!("https://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);
    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg.unwrap())
        .send()
        .expect("Problem starting keep");

    let keep_response = from_slice(&cbor_response.bytes().unwrap());
    match keep_response {
        Ok(keep) => Ok(keep),
        Err(e) => {
            println!("Problem with keep response {}", e);
            Err("Error with response".to_string())
        }
    }
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
