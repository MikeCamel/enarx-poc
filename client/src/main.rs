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

//https://github.com/mehcode/config-rs/tree/master/examples/simple/src
use config::*;
use koine::*;
use serde_cbor::{from_slice, to_vec};
use std::io;
use std::path::Path;

//currently only one Keep-Manager and one Keep supported
fn main() {
    let mut settings = config::Config::default();
    settings
        // Add in `./Settings.toml`
        .merge(config::File::with_name("Client_config"))
        .unwrap()
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::with_prefix("client"))
        .unwrap();

    let mut user_input = String::new();
    println!("/nWelcome to the Enarx client.");
    println!("We will step through a number of tests.  First ensure that you are running a");
    println!("Keep manager on localhost port 3030 (the default).");

    //list available keepmgrs if applicable
    let keepmgr_addr: String = settings.get("keepmgr_address").unwrap();
    let keepmgr_port: u16 = settings.get("keepmgr_port").unwrap();
    let keepmgr = KeepMgr {
        address: keepmgr_addr.to_string(),
        port: keepmgr_port,
    };

    println!();
    println!("First we will contact the Keep manager and list available contracts");
    println!("********************************");
    println!("Press <Enter>");
    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //for a particular keepmgr, retrieve list of available contracts
    let keepcontracts: Vec<KeepContract> = list_contracts(&keepmgr).unwrap();
    println!();
    if keepcontracts.len() == 0 {
        println!("No contracts available");
    } else {
        for i in 0..keepcontracts.len() {
            println!(
                "Contract available for a {} Keep, uuid = {:?}",
                keepcontracts[i].backend.as_str(),
                keepcontracts[i].uuid
            );
        }
        println!();
        println!("We will create one of each supported type");
    }
    println!("********************************");
    println!("Press <Enter>");
    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //create keeps
    let mut keep_result_vec: Vec<Keep> = Vec::new();
    for contract in keepcontracts.iter() {
        if settings.get(contract.backend.as_str()).unwrap() {
            println!("Keeps of type {} are acceptable", contract.backend.as_str());

            let keep_result: Keep = new_keep(&keepmgr, &contract).unwrap();
            println!(
                "Received keep, kuuid = {:?}, backend = {}",
                keep_result.kuuid,
                keep_result.backend.as_str()
            );
            println!();
            println!("Connect to the created Keep (for attestation, etc.)");
            println!("********************************");
            println!("Press <Enter>");
            io::stdin()
                .read_line(&mut user_input)
                .expect("Failed to read line");

            //TEST: connect to specific keep
            let comms_complete: CommsComplete =
                test_keep_connection(&keepmgr, &keep_result).unwrap();
            match comms_complete {
                CommsComplete::Success => println!("Success connecting to {}", &keep_result.kuuid),
                CommsComplete::Failure => println!("Failure connecting to {}", &keep_result.kuuid),
            }
            println!("");
            keep_result_vec.push(keep_result);
        }
    }

    /*
    //TEST - re-check availability of contracts
    //for a particular keepmgr, retrieve list of available contracts
    let keepcontracts2: Vec<KeepContract> = list_contracts(&keepmgr).unwrap();
    println!();
    if keepcontracts2.len() == 0 {
        println!("No contracts available");
    }
    for i in 0..keepcontracts2.len() {
        println!(
            "Contract available for a {} Keep, uuid = {:?}",
            keepcontracts2[i].backend.as_str(),
            keepcontracts2[i].uuid
        );
    }
    */
    println!();
    println!("We will attempt to connect to the first Keep and send a wasm workload");
    println!("********************************");
    println!("Press <Enter>");
    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //use the first result
    for i in 0..keep_result_vec.len() {
        //  if keep_result_vec.len() > 0 {
        let mut chosen_keep = keep_result_vec[i].clone();
        //perform attestation
        //steps required will depend on backend

        //get certificate from keepldr
        //get address & port
        //TODO - if this fails, we need to panic

        match get_keep_wasmldr(&chosen_keep, &settings) {
            Ok(wl) => chosen_keep.wasmldr = Some(wl),
            Err(e) => panic!("No wasmloader found: {}", e),
        }
        //STATE: keep ready for us to connect to it

        //disconnect from keepmgr

        //choose wasm workload
        let workload: Workload = retrieve_workload(&settings).unwrap();
        //connect to wasmldr via HTTPS
        // (note validate server against certificate received above)

        //send wasm workload
        let provision_result = provision_workload(&chosen_keep, &workload);
        match provision_result {
            Ok(_b) => println!("Successfully sent workload!"),
            Err(e) => println!("Had a problem with sending workload: {}", e),
        }
    }
}

pub fn list_hosts() -> Result<Vec<KeepMgr>, String> {
    Err("Unimplemented".to_string())
}

pub fn list_contracts(keepmgr: &KeepMgr) -> Result<Vec<KeepContract>, String> {
    let keep_mgr_url = format!("http://{}:{}/contracts/", keepmgr.address, keepmgr.port);
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

    let keep_mgr_url = format!("http://{}:{}/new_keep/", keepmgr.address, keepmgr.port);
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

pub fn test_keep_connection(keepmgr: &KeepMgr, keep: &Keep) -> Result<CommsComplete, String> {
    let keep_mgr_url = format!(
        "http://{}:{}/keep/{}",
        keepmgr.address, keepmgr.port, keep.kuuid
    );
    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .send()
        .expect("Problem connecting to keep");

    let contractvec_response = from_slice(&cbor_response.bytes().unwrap());
    match contractvec_response {
        Ok(cc) => Ok(cc),
        Err(e) => {
            println!("Problem with keep response {}", e);
            Err("Error with response".to_string())
        }
    }
}

pub fn get_keep_wasmldr(_keep: &Keep, settings: &Config) -> Result<Wasmldr, String> {
    //TODO - implement with information passed via keepmgr
    let wasmldr_addr: String = settings.get("wasmldr_address").unwrap();
    let wasmldr_port: u16 = settings.get("wasmldr_port").unwrap();
    let wasmldr = Wasmldr {
        wasmldr_ipaddr: wasmldr_addr.to_string(),
        wasmldr_port: wasmldr_port,
    };
    Ok(wasmldr)
}

pub fn retrieve_workload(settings: &Config) -> Result<Workload, String> {
    //TODO - add loading of files from command-line
    let workload_path: String = settings.get("workload_path").unwrap();
    let in_path = Path::new(&workload_path);
    //    let in_path = Path::new("external/return_1.wasm");

    let in_contents = match std::fs::read(in_path) {
        Ok(in_contents) => {
            println!("Contents = of {} bytes", &in_contents.len());
            in_contents
        }
        Err(_) => {
            println!("Failed to read from file");
            panic!("We have no data to use");
        }
    };

    let workload = Workload {
        human_readable_info: String::from("wasm"),
        wasm_binary: in_contents,
    };
    Ok(workload)
}

pub fn provision_workload(keep: &Keep, workload: &Workload) -> Result<bool, String> {
    let cbor_msg = to_vec(&workload);
    let wasmldr: &Wasmldr;
    match &keep.wasmldr {
        None => panic!("No details available to connect to wasmldr"),
        Some(wl) => wasmldr = wl,
    }
    /*
    //add client certificate presentation
    let client_cert_path: &str = "key-material/client.p12";
    let mut cert_buf = Vec::new();

    File::open(&client_cert_path)
        .expect("certificate opening problems")
        .read_to_end(&mut cert_buf)
        .expect("certificate file reading problems");
    //DANGER, DANGER - password hard-coded
    //DANGER, DANGER - password in clear-text
    //FIXME, FIXME
    let pkcs12_client_id = reqwest::Identity::from_pkcs12_der(&cert_buf, "enarx-test")
        .expect("certificate reading problems");
     */
    let connect_uri = format!(
        "https://{}:{}/payload",
        wasmldr.wasmldr_ipaddr, wasmldr.wasmldr_port
    );

    //we accept invalid certs here because in the longer term, we will have a mechanism
    // for finding out what the cert should be dynamically, and adding it, but currently,
    // we don't know what to expect as cert is dynamically generated and self-signed
    //TODO: add certs dynamically as part of protocol

    println!("About to send a workload to {}", &connect_uri);
    let _res = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        //.identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .body(cbor_msg.unwrap())
        .send();
    //NOTE - as the wasmldr exits once the payload has been executed, this
    // should actually error out
    //println!("{:#?}", res);
    Ok(true)
}

/*
    //TEST 1 - localhost:port
    let connect_uri = format!("https://localhost:{}/payload", connect_port);
    //TEST 2 - other_add:port
    //let connect_uri = format!("https://{}:{}/payload", LOCAL_LISTEN_ADDRESS, connect_port);

*/
