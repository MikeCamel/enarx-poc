// SPDX-License-Identifier: Apache-2.0

//! This crate provides the Enarx client
//!
//! # Build
//!
//!     $ git clone https://github.com/enarx/enarx
//!     $ cd enarx
//!     $ cargo build
//!
//! # Run
//!
//! Edit Client_config.toml
//!     $ cargo run
//!   OR
//!     $ cargo run <path_to_.wasm_file>

#![deny(clippy::all)]
extern crate reqwest;

//use ciborium::de::*;
//use ciborium::ser::*;
use config::*;
use koine::*;
//use koine::threading::lists::*;
use std::convert::TryFrom;
use std::io;
//use std::os::unix::net::UnixStream;
use std::path::Path;

use sev::*;
use sev::launch::Policy;
use sev::session::Session;
//use enarx-keepldr::sev::certs::{ca, sev};
//use enarx-keepldr::sev::launch::Policy;
//use enarx-keepldr::sev::session::Session;
//use sev::*;
//use sev::certs::{ca, sev};
//use sev::launch::Policy;
//use sev::session::Session;
use koine::attestation::sev::*;
//use ::sev::certs::{ca, sev};
//use ::sev::launch::Policy;
//use ::sev::session::Session;

use ciborium::{de::from_reader, ser::into_writer};
//use codicon::{Decoder, Encoder};

//currently only one Keep-Manager and one Keep supported
fn main() {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("Client_config"))
        .unwrap()
        .merge(config::Environment::with_prefix("client"))
        .unwrap();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut user_input = String::new();
    println!("\nWelcome to the Enarx client.");

    if args.len() > 0 {
        settings.set("user_workload", args[0].clone()).unwrap();
        println!(
            "Received wasm workload {}\n",
            settings.get_str("user_workload").unwrap()
        );
    }
    //list available keepmgrs if applicable
    let keepmgr_addr: String = settings.get("keepmgr_address").unwrap();
    let keepmgr_port: u16 = settings.get("keepmgr_port").unwrap();
    let keepmgr = KeepMgr {
        //        address: keepmgr_addr.to_string(),
        address: keepmgr_addr,
        port: keepmgr_port,
    };
    println!("We will step through a number of tests.  First ensure that you are running a");
    println!(
        "Keep manager on '{}:{}' (as specified in Client_config.toml).",
        keepmgr.address, keepmgr.port
    );

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
    if keepcontracts.is_empty() {
        println!("No contracts available");
    } else {
        for contract in keepcontracts.iter() {
            println!(
                "Contract available for a {} Keep, uuid = {:?}",
                contract.backend.as_str(),
                contract.uuid
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

            let comms_complete: CommsComplete;
            if keep_result.backend == Backend::Sev {
                //pre-attestation required
                comms_complete = attest_keep(&keepmgr, &keep_result).unwrap();
            } else {
                //TEST: connect to specific keep
                comms_complete = test_keep_connection(&keepmgr, &keep_result).unwrap();
            }
            match comms_complete {
                CommsComplete::Success => println!("Success connecting to {}", &keep_result.kuuid),
                CommsComplete::Failure => println!("Failure connecting to {}", &keep_result.kuuid),
            }
            println!();
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

    for keep in keep_result_vec.iter() {
        let mut chosen_keep = keep.clone();
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
        println!("Ready for next keep?");
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

    let cbytes: &[u8] = &cbor_response.bytes().unwrap();
    println!("cbytes len = {}", cbytes.len());
    let crespbytes = cbytes.as_ref();
    let contractvec: Vec<KeepContract> = from_reader(&crespbytes[..]).unwrap();

    Ok(contractvec)
}

pub fn new_keep(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Keep, String> {
    //    let cbor_msg = to_vec(&keepcontract);
    let mut cbor_msg = Vec::new();
    into_writer(&keepcontract, &mut cbor_msg).unwrap();

    let keep_mgr_url = format!("http://{}:{}/new_keep/", keepmgr.address, keepmgr.port);
    //removing HTTPS for now, due to certificate issues
    //let keep_mgr_url = format!("https://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);
    println!("About to connect on {}", keep_mgr_url);
    println!("Sending {:02x?}", &cbor_msg);

    //------------- TEST
    let contract: KeepContract = from_reader(&cbor_msg[..]).unwrap();
    println!("bytes = {:02x?}", &contract);
    //------------- END TEST

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        //removing HTTPS for now, due to certificate issues
        //.danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg)
        .send()
        .expect("Problem starting keep");

    let kbytes: &[u8] = &cbor_response.bytes().unwrap();
    let keepbytes = kbytes.as_ref();
    let keep: Keep = from_reader(keepbytes).unwrap();
    Ok(keep)
}

pub fn attest_keep(keepmgr: &KeepMgr, keep: &Keep) -> Result<CommsComplete, String> {
    if keep.backend == Backend::Sev {
        let keep_mgr_url = format!(
            "http://{}:{}/keep/{}",
            keepmgr.address, keepmgr.port, keep.kuuid
        );
        sev_pre_attest(keep_mgr_url, keep)
    } else {
        Err(format!("Unimplemented for {}", keep.backend.as_str()))
    }
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

    let cbytes: &[u8] = &cbor_response.bytes().unwrap();
    let crespbytes = cbytes;
    let response: CommsComplete = from_reader(crespbytes).unwrap();
    Ok(response)
}

pub fn get_keep_wasmldr(_keep: &Keep, settings: &Config) -> Result<Wasmldr, String> {
    //TODO - implement with information passed via keepmgr
    let wasmldr_addr: String = settings.get("wasmldr_address").unwrap();
    let wasmldr_port: u16 = settings.get("wasmldr_port").unwrap();
    let wasmldr = Wasmldr {
        wasmldr_ipaddr: wasmldr_addr,
        wasmldr_port,
    };
    Ok(wasmldr)
}

pub fn retrieve_workload(settings: &Config) -> Result<Workload, String> {
    //TODO - add loading of files from command-line
    //let workload_path: String = settings.get("workload_path").unwrap();
    let workload_path: String = match settings.get_str("user_workload") {
        Ok(user_workload) => user_workload,
        Err(_) => settings.get("workload_path").unwrap(),
    };
    let in_path = Path::new(&workload_path);

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
    //    let cbor_msg = to_vec(&workload);
    let mut cbor_msg = Vec::new();
    into_writer(&workload, &mut cbor_msg).unwrap();

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
        "https://{}:{}/workload",
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
        //    .body(cbor_msg.unwrap())
        .body(cbor_msg)
        .send();
    //NOTE - as the wasmldr exits once the payload has been executed, this
    // should actually error out
    //println!("{:#?}", res);
    Ok(true)
}


pub fn sev_pre_attest(keepmgr_url: String, keep: &Keep) -> Result<CommsComplete, String> {
    //FIXME!!!!! (entire function)
    const DIGEST: [u8; 32] = [
        171, 137, 63, 183, 79, 113, 206, 32, 82, 187, 235, 156, 158, 168, 181, 49, 243, 102, 178,
        74, 22, 242, 132, 204, 168, 84, 98, 63, 151, 249, 142, 229,
    ];

    //TODO - make this a private key
    const CLEARTEXT: &'static str = "\
Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!\
Hello World!!Hello World!\
";

    let response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keepmgr_url)
        .send()
    .   expect("Problem connecting to keep");
    let crespbytes = &response.bytes().unwrap();
    
    //TODO - identify which type of chain?
    //TODO - error handling
    let chain_res: Message = from_reader(&crespbytes[..]).unwrap();
    let chain = match chain_res {
        Message::CertificateChainNaples(chain) => chain,
        Message::CertificateChainRome(chain) => chain,
        _ => panic!("expected certificate chain"),
    };

    let policy = Policy::default();
    let session = Session::try_from(policy).expect("failed to craft policy");

    let start = session.start(chain).expect("failed to start session");
    let start_packet = Message::LaunchStart(start);
    
    let mut cbor_start_packet = Vec::new();
    into_writer(&start_packet, &mut cbor_start_packet).unwrap();

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
    //removing HTTPS for now, due to certificate issues
    //.danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keepmgr_url)
        .body(cbor_start_packet)
        .send()
        .expect("Problem starting keep");
    let crespbytes = &cbor_response.bytes().unwrap();
    let msr: Message = from_reader(&crespbytes[..]).unwrap();
    assert!(matches!(msr, Message::Measurement(_)));

    let secret_packet = if let Message::Measurement(msr) = msr {
        let build: Build = msr.build;

        let measurement: sev::launch::Measurement = msr.measurement;

        let session = session
            .verify(&DIGEST, build, measurement)
            .expect("verify failed");

        let ct_vec = CLEARTEXT.as_bytes().to_vec();
        let mut ct_enc = Vec::new();
        into_writer(&mut ct_enc, ct_vec);

        let secret = session
            .secret(::sev::launch::HeaderFlags::default(), &ct_enc)
            .expect("gen_secret failed");

        println!("Sent secret: {:?}", CLEARTEXT);
        println!("Sent secret len: {}", ct_enc.len());

        //let mut s_enc = Vec::new();
        //into_writer(&secret, &mut s_enc).unwrap();
        //Message::Secret(s_enc)
        Message::Secret(Some(secret))
    } else {
        //Message::Secret(vec![])
        Message::Secret(None)
    };


//serde_flavor::to_writer(&sock, &secret_packet).expect("failed to serialize secret packet");
    let mut cbor_secret_msg = Vec::new();
    into_writer(&secret_packet, &mut cbor_secret_msg).unwrap();
    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
    //removing HTTPS for now, due to certificate issues
    //.danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keepmgr_url)
        .body(cbor_secret_msg)
        .send()
    .expect("Problem starting keep");

    //let fin = Message::deserialize(&mut de).expect("failed to deserialize expected finish packet");
    let crespbytes = &cbor_response.bytes().unwrap();
    let fin: Message = from_reader(&crespbytes[..]).unwrap();

    assert!(matches!(fin, Message::Finish(_)));
    //********************* */
    //FIXME - actually needs testing
    Ok(CommsComplete::Success)
}
