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

use ciborium::de::*;
use ciborium::ser::*;
use config::*;
use koine::*;
use std::convert::TryFrom;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

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
use codicon::{Decoder, Encoder};

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
    //FIXME!!!!!
    const DIGEST: [u8; 32] = [
        171, 137, 63, 183, 79, 113, 206, 32, 82, 187, 235, 156, 158, 168, 181, 49, 243, 102, 178,
        74, 22, 242, 132, 204, 168, 84, 98, 63, 151, 249, 142, 229,
    ];

    const CLEARTEXT: &'static str = "\
Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!Hello World!!\
Hello World!!Hello World!\
";

    let response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keepmgr_url)
        .send()
        .expect("Problem connecting to keep");
    let crespbytes = &response.bytes().unwrap();
    let chain_packet: Message = from_reader(&crespbytes[..]).unwrap();

    let chain_packet = match chain_packet {
        Message::CertificateChainNaples(chain) => chain,
        Message::CertificateChainRome(chain) => chain,
        _ => panic!("expected certificate chain"),
    };

    let chain = ::sev::certs::Chain {
        ca: ::sev::certs::ca::Chain {
            ark: ::sev::certs::ca::Certificate::decode(chain_packet.ark.as_slice(), ())
                .expect("ark"),
            ask: ::sev::certs::ca::Certificate::decode(chain_packet.ask.as_slice(), ())
                .expect("ask"),
        },
        sev: ::sev::certs::sev::Chain {
            pdh: ::sev::certs::sev::Certificate::decode(chain_packet.pdh.as_slice(), ())
                .expect("pdh"),
            pek: ::sev::certs::sev::Certificate::decode(chain_packet.pek.as_slice(), ())
                .expect("pek"),
            cek: ::sev::certs::sev::Certificate::decode(chain_packet.cek.as_slice(), ())
                .expect("cek"),
            oca: ::sev::certs::sev::Certificate::decode(chain_packet.oca.as_slice(), ())
                .expect("oca"),
        },
    };

    let policy = ::sev::launch::Policy::default();
    let session = ::sev::session::Session::try_from(policy).expect("failed to craft policy");

    //from https://gist.github.com/haraldh/9ef6f03987e9c22d9ee41f2ca88e55ad

    let start = session.start(chain).expect("failed to start session");
    let mut ls = LaunchStart {
        policy: vec![],
        cert: vec![],
        session: vec![],
    };

    ciborium::ser::into_writer(&start.policy, &mut ls.policy).expect("failed to serialize policy");
    start
        .cert
        .encode(&mut ls.cert, ())
        .expect("start cert encode");
    into_writer(&start.session, &mut ls.session).expect("failed to serialize session");

    let start = session.start(chain).expect("failed to start session");
    let mut ls = LaunchStart {
        policy: vec![],
        cert: vec![],
        session: vec![],
    };
    //serde_flavor::to_writer(&mut ls.policy, &start.policy).expect("failed to serialize policy");
    ciborium::ser::into_writer(&mut ls.policy, &start.policy).expect("failed to serialize policy");
    start
        .cert
        .encode(&mut ls.cert, ())
        .expect("start cert encode");
    //serde_flavor::to_writer(&mut ls.session, &start.session).expect("failed to serialize session");
    ciborium::ser::into_writer(&mut ls.session, &start.session)
        .expect("failed to serialize session");

    let start_packet = Message::LaunchStart(ls);
    //TODO - use reqwest
    //    serde_flavor::to_writer(&sock, &start_packet).expect("failed to serialize launch start");
    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        //removing HTTPS for now, due to certificate issues
        //.danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keepmgr_url)
        //TODO - check this is already CBORred
        .body(start_packet)
        .send()
        .expect("Problem starting keep");
    let crespbytes = &response.bytes().unwrap();
    let msr: Message = from_reader(&crespbytes[..]).unwrap();

    //let msr =
    //    Message::deserialize(&mut de).expect("failed to deserialize expected measurement packet");
    assert!(matches!(msr, Message::Measurement(_)));

    let secret_packet = if let Message::Measurement(msr) = msr {
        let build: ::sev::Build =
            //serde_flavor::from_slice(&msr.build).expect("failed to deserialize build");
            from_slice(&msr.build).expect("failed to deserialize build");

        let measurement: ::sev::launch::Measurement =
            //serde_flavor::from_slice(&msr.measurement).expect("failed to deserialize measurement");
            from_slice(&msr.measurement).expect("failed to deserialize measurement");

        let session = session
            .verify(&DIGEST, build, measurement)
            .expect("verify failed");

        let ct_vec = CLEARTEXT.as_bytes().to_vec();
        let mut ct_enc = Vec::new();
        //serde_flavor::ser::to_writer(&mut ct_enc, &serde_cbor::value::Value::Bytes(ct_vec))
        ciborium::ser::into_writer(&mut ct_enc, &serde_cbor::value::Value::Bytes(ct_vec))
            .expect("failed to encode secret");

        let secret = session
            .secret(::sev::launch::HeaderFlags::default(), &ct_enc)
            .expect("gen_secret failed");

        println!("Sent secret: {:?}", CLEARTEXT);
        println!("Sent secret len: {}", ct_enc.len());

        //let s_enc = serde_flavor::to_vec(&secret).expect("failed to serialize secret to vector");
        let s_enc = to_vec(&secret).expect("failed to serialize secret to vector");

        Message::Secret(s_enc)
    } else {
        Message::Secret(vec![])
    };

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        //removing HTTPS for now, due to certificate issues
        //.danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(&keepmgr_url)
        //TODO - check this is already CBORred
        .body(secret_packet)
        .send()
        .expect("Problem starting keep");
    let crespbytes = &response.bytes().unwrap();
    let fin: Message = from_reader(&crespbytes[..]).unwrap();

    //serde_flavor::to_writer(&sock, &secret_packet).expect("failed to serialize secret packet");
    //let fin = Message::deserialize(&mut de).expect("failed to deserialize expected finish packet");
    assert!(matches!(fin, Message::Finish(_)));
    //FIXME
    Err(format!("Failure"))

    /*
    //OLD - from connor
    let start_packet = Message::LaunchStart(ls);
    //TODO - send this using reqwest body
    into_writer(&start_packet, &sock).expect("failed to serialize launch start");

    //FIXME - we _do_ care!
    // Discard the measurement, the synthetic client doesn't care
    // for an unattested launch.
    //TODO - get a response back
    let msr = from_reader(&sock).expect("failed to deserialize expected measurement packet");
    assert!(matches!(msr, Message::Measurement(_)));

    let secret_packet = Message::Secret(vec![]);
    //TODO - send this using reqwest body
    into_writer(&secret_packet, &sock).expect("failed to serialize secret packet");

    //TODO - get a response back
    let fin = from_reader(&sock).expect("failed to deserialize expected finish packet");
    assert!(matches!(fin, Message::Finish(_)));

    //FIXME
    Err(format!("Failure"))
    */
}
