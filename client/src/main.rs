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
use std::io;
use std::net::{IpAddr, Ipv4Addr};

//currently only one Keep-Manager and one Keep supported
fn main() {
    let mut user_input = String::new();
    println!("Welcome to the Enarx client.");
    println!("We will step through a number of tests.  First ensure that you are running a");
    println!("Keep manager on localhost port 3030 (the default).");

    //list available keepmgrs
    // - currently only localhost supported
    let my_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let keepmgr = KeepMgr {
        ipaddr: my_addr,
        port: 3030,
    };

    println!();
    println!("First we will contact the Keep manager and list available contracts");
    println!("Press <Enter>");
    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //for a particular keepmgr, retrieve list of available contracts
    let keepcontracts: Vec<KeepContract> = list_contracts(&keepmgr).unwrap();
    println!();
    for i in 0..keepcontracts.len() {
        println!(
            "Contract available for a {} Keep",
            keepcontracts[i].backend.as_str(),
        );
    }

    //create keeps
    println!();
    println!("We will create one of each");
    for contract in keepcontracts.iter() {
        let keep_result: Keep = new_keep(&keepmgr, &contract).unwrap();
        println!(
            "Received keep, kuuid = {:?}, backend = {}",
            keep_result.kuuid,
            keep_result.backend.as_str()
        );
        println!();
    }

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
    let keep_mgr_url = format!("http://{}:{}/list_contracts/", keepmgr.ipaddr, keepmgr.port);
    //removing HTTPS for now, due to certificate issues
    //let keep_mgr_url = format!(
    //    "https://{}:{}/list-contracts/",
    //    keepmgr.ipaddr, keepmgr.port
    //);
    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        //removing HTTPS for now, due to certificate issues
        //.danger_accept_invalid_certs(true)
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

pub fn new_keep(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Keep, String> {
    let cbor_msg = to_vec(&keepcontract);

    let keep_mgr_url = format!("http://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);
    //removing HTTPS for now, due to certificate issues
    //let keep_mgr_url = format!("https://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);
    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        //removing HTTPS for now, due to certificate issues
        //.danger_accept_invalid_certs(true)
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
