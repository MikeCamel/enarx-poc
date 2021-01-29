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

use config::*;
use koine::attestation::sev::*;
use koine::*;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sha;
use openssl::ssl::*;
use sev::launch::Policy;
use sev::session::Session;
use sev::*;
use std::convert::TryFrom;
use std::io;
use std::path::{Path, PathBuf};
use std::time::*;
use structopt::StructOpt;
use sys_info::*;
//use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
//use openssl::x509::{X509StoreContextRef, X509, X509NameRef};
use openssl::nid::*;
use openssl::x509::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
//use x509_parser::*;

use ciborium::{de::from_reader, ser::into_writer};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
pub struct Interactive {}

#[derive(StructOpt)]
pub struct Deploy {
    payload: PathBuf,
    keepmgr_addr: String,
    keepmgr_port: u16,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    //Info(Info),
    Deploy(Deploy),
    Interactive(Interactive),
}

#[allow(clippy::unnecessary_wraps)]
//currently only one Keep-Manager and one Keep supported
fn main() {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("Client_config"))
        .unwrap()
        .merge(config::Environment::with_prefix("client"))
        .unwrap();

    match Options::from_args() {
        Options::Deploy(e) => deploy(e, &mut settings),
        Options::Interactive(e) => interactive(e, &mut settings),
    }
}

pub fn deploy(deploy: Deploy, settings: &mut Config) {
    //TODO - implement
    let keepmgr = KeepMgr {
        address: deploy.keepmgr_addr,
        port: deploy.keepmgr_port,
    };
    let _try_uw = settings.set("user_workload", deploy.payload.to_str());
    let keepcontracts: Vec<KeepContract> = list_contracts(&keepmgr).unwrap();
    if keepcontracts.is_empty() {
        panic!("No contracts available");
    }

    let mut keep_result_vec: Vec<Keep> = Vec::new();
    for contract in keepcontracts.iter() {
        if settings.get(contract.backend.as_str()).unwrap() {
            println!("Keeps of type {} are acceptable", contract.backend.as_str());

            let mut keep_result: Keep = new_keep(&keepmgr, &contract).unwrap();
            println!(
                "Received keep, kuuid = {:?}, backend = {}",
                keep_result.kuuid,
                keep_result.backend.as_str()
            );
            match get_keep_wasmldr(&keep_result, &settings) {
                Ok(wl) => {
                    println!("Added wasmldr to chosen_keep");
                    keep_result.wasmldr = Some(wl)
                }
                Err(e) => panic!("No wasmloader found: {}", e),
            }
            //println!();
            println!("\nConnecting to the created Keep (for attestation, etc.)");

            let comms_complete: CommsComplete;
            if keep_result.backend == Backend::Sev {
                //pre-attestation required
                let digest: [u8; 32] = settings.get("sev-digest").unwrap();
                comms_complete = attest_keep(&keepmgr, &mut keep_result, digest)
                    .expect("Incomplete, missing or misformatted measurement data");
            } else {
                //TEST: connect to specific keep
                comms_complete = test_keep_connection(&keepmgr, &keep_result).unwrap();
            }
            match comms_complete {
                CommsComplete::Success => println!("Success connecting to {}", &keep_result.kuuid),
                CommsComplete::Failure => println!("Failure connecting to {}", &keep_result.kuuid),
            }
            keep_result_vec.push(keep_result);
        }
    }
    for keep in keep_result_vec.iter() {
        let chosen_keep = keep.clone();
        //perform attestation
        //steps required will depend on backend

        //get certificate from keepldr
        //TODO - if this fails, we need to panic

        //STATE: keep ready for us to connect to it

        //choose wasm workload
        // TODO - check certificate
        let workload: Workload = retrieve_workload(&settings).unwrap();
        //connect to wasmldr via HTTPS

        //send wasm workload
        let provision_result = provision_workload(&chosen_keep, &workload);
        match provision_result {
            Ok(_b) => println!("Successfully sent workload!"),
            Err(e) => println!("Had a problem with sending workload: {}", e),
        }
        //execute workload
        //let run_result = run_workload(&chosen_keep);
    }
}

pub fn interactive(_interactive: Interactive, settings: &mut Config) {
    //FIXME - not maintained

    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut user_input = String::new();
    println!("\nWelcome to the Enarx client.");

    if args.len() > 1 {
        settings.set("user_workload", args[1].clone()).unwrap();
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

    let myhostname = hostname().unwrap();
    println!("We are running on host '{}'", myhostname);

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

            let mut keep_result: Keep = new_keep(&keepmgr, &contract).unwrap();
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
                let digest: [u8; 32] = settings.get("sev-digest").unwrap();
                comms_complete = attest_keep(&keepmgr, &mut keep_result, digest).unwrap();
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

        //choose wasm workload
        // TODO - check certificate
        let workload: Workload = retrieve_workload(&settings).unwrap();
        //connect to wasmldr via HTTPS

        //send wasm workload
        let provision_result = provision_workload(&chosen_keep, &workload);
        match provision_result {
            Ok(_b) => println!("Successfully sent workload!"),
            Err(e) => println!("Had a problem with sending workload: {}", e),
        }
        //execute workload
        let _run_result = run_workload(&chosen_keep);
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
    println!("\nAbout to connect on {}", keep_mgr_url);

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
    //println!("cbytes len = {}", cbytes.len());
    let crespbytes = cbytes.as_ref();
    let contractvec: Vec<KeepContract> = from_reader(&crespbytes[..]).unwrap();

    Ok(contractvec)
}

pub fn new_keep(keepmgr: &KeepMgr, keepcontract: &KeepContract) -> Result<Keep, String> {
    let mut cbor_msg = Vec::new();
    into_writer(&keepcontract, &mut cbor_msg).unwrap();

    let keep_mgr_url = format!("http://{}:{}/new_keep/", keepmgr.address, keepmgr.port);
    //removing HTTPS for now, due to certificate issues
    //let keep_mgr_url = format!("https://{}:{}/new_keep/", keepmgr.ipaddr, keepmgr.port);
    println!("\nAbout to connect on {}", keep_mgr_url);
    //println!("Sending {:02x?}", &cbor_msg);

    let _contract: KeepContract = from_reader(&cbor_msg[..]).unwrap();
    //println!("bytes = {:02x?}", &contract);

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

pub fn attest_keep(
    keepmgr: &KeepMgr,
    keep: &mut Keep,
    digest: [u8; 32],
) -> Result<CommsComplete, String> {
    if keep.backend == Backend::Sev {
        let keep_mgr_url = format!(
            "http://{}:{}/keep/{}",
            keepmgr.address, keepmgr.port, keep.kuuid
        );
        sev_pre_attest(keep_mgr_url, keep, digest)
    } else {
        Err(format!("Unimplemented for {}", keep.backend.as_str()))
    }
}

pub fn test_keep_connection(keepmgr: &KeepMgr, keep: &Keep) -> Result<CommsComplete, String> {
    let keep_mgr_url = format!(
        "http://{}:{}/keep/{}",
        keepmgr.address, keepmgr.port, keep.kuuid
    );

    let dummy_msg = String::from("Test message");
    let mut cbor_msg = Vec::new();
    into_writer(&dummy_msg, &mut cbor_msg).unwrap();

    println!("About to connect on {}", keep_mgr_url);

    let cbor_response: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keep_mgr_url)
        .body(cbor_msg)
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
    println!("Creating wasmldr entry {}:{}", wasmldr_addr, wasmldr_port);
    let wasmldr = Wasmldr {
        wasmldr_ipaddr: wasmldr_addr,
        wasmldr_port,
    };
    Ok(wasmldr)
}

pub fn retrieve_workload(settings: &Config) -> Result<Workload, String> {
    let workload_path: String = match settings.get_str("user_workload") {
        Ok(user_workload) => user_workload,
        Err(_) => settings.get("workload_path").unwrap(),
    };
    let in_path = Path::new(&workload_path);
    println!("Taking workload from {}", &workload_path);

    let in_contents = match std::fs::read(in_path) {
        Ok(in_contents) => {
            println!("Contents of payload = {} bytes", &in_contents.len());
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

pub fn run_workload(keep: &Keep) -> Result<bool, String> {
    let wasmldr: &Wasmldr;
    match &keep.wasmldr {
        None => panic!("No details available to connect to wasmldr"),
        Some(wl) => wasmldr = wl,
    }
    let connect_uri = format!(
        "https://{}:{}/run",
        wasmldr.wasmldr_ipaddr, wasmldr.wasmldr_port
    );
    //TODO - add client certificate?
    //default to requiring a matching certificate
    let mut certificate_required = true;
    //some backends do not provide certificates we can check
    if keep.backend == Backend::Nil {
        certificate_required = false;
    }
    if keep.backend == Backend::Kvm {
        certificate_required = false;
    }
    let workload_run_res: Result<bool, String>;
    if certificate_required {
        println!("Attempting to retrieve certificate to check against wasmldr HTTPS");
        match &keep.certificate_as_pem {
            Some(certificate_as_pem) => {
                let certificate_res = reqwest::Certificate::from_pem(&certificate_as_pem);
                match certificate_res {
                    Ok(certificate) => {
                        println!("\nAbout to start a workload on {}", &connect_uri);
                        match cert_run(certificate, connect_uri) {
                            Ok(_) => workload_run_res = Ok(true),
                            Err(e) => workload_run_res = Err(e.to_string()),
                        }
                    }
                    Err(_e) => {
                        workload_run_res = Err(String::from(
                            "Unable to create certificate from available data.",
                        ))
                    }
                }
            }
            None => {
                workload_run_res = Err(String::from(
                    "No public key available to build certificate.",
                ))
            }
        }
    } else {
        println!("\nAbout start a workload on {}", &connect_uri);
        match no_cert_run(connect_uri) {
            Ok(_) => workload_run_res = Ok(true),
            Err(_e) => {
                //FIXME - Currently, wasmldr drops the connection unceremoniously, making it look
                // like provisioning failed.  For now, we'll give an "OK" here
                //Err(e.to_string())
                workload_run_res = Ok(true);
                //workload_provision_res = Err(e.to_string())
            }
        }
    }
    workload_run_res
}

pub fn provision_workload(keep: &Keep, workload: &Workload) -> Result<bool, String> {
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

    //default to requiring a matching certificate
    let mut certificate_required = true;
    //some backends do not provide certificates we can check
    if keep.backend == Backend::Nil {
        certificate_required = false;
    }
    if keep.backend == Backend::Kvm {
        certificate_required = false;
    }
    if keep.backend == Backend::Sgx {
        //get a certificate (using get_cert_from_https)
        let sgx_cert = get_cert_from_https(wasmldr.clone());
        //hash the public key from the certificate
        let pub_key = &sgx_cert.public_key().unwrap();
        let pub_key_pem = pub_key.public_key_to_pem().unwrap();
        let mut hasher = sha::Sha256::new();
        hasher.update(&pub_key_pem);
        let pub_key_hash = hasher.finish();

        //get the attestation_data from the certificate
        let attestation_base64 = sgx_cert.subject_name().entries_by_nid(Nid::USERCERTIFICATE).next().unwrap().data().as_utf8().unwrap().to_string();
        let attestation_data = base64::decode(attestation_base64).unwrap();
        //TODO - implement verify call
        //perform an attestation::verify with the attestation data, key_chain & sgx pre-measure data
        //check that the output from the verify == the hash of the public key from the certificate
        //if good, do a cert_provisioning with the certificate (this last is important in case
        //the new connection is forged)
    }
    let workload_provision_res: Result<bool, String>;
    if certificate_required {
        println!("Attempting to retrieve certificate to check against wasmldr HTTPS");
        match &keep.certificate_as_pem {
            Some(certificate_as_pem) => {
                let certificate_res = reqwest::Certificate::from_pem(&certificate_as_pem);
                match certificate_res {
                    Ok(certificate) => {
                        println!("\nAbout to send a workload to {}", &connect_uri);
                        match cert_provisioning(certificate, connect_uri, cbor_msg) {
                            Ok(_) => workload_provision_res = Ok(true),
                            Err(e) => workload_provision_res = Err(e.to_string()),
                        }
                    }
                    Err(_e) => {
                        workload_provision_res = Err(String::from(
                            "Unable to create certificate from available data.",
                        ))
                    }
                }
            }
            None => {
                workload_provision_res = Err(String::from(
                    "No public key available to build certificate.",
                ))
            }
        }
    } else {
        println!("\nAbout to send a workload to {}", &connect_uri);
        match no_cert_provisioning(connect_uri, cbor_msg) {
            Ok(_) => workload_provision_res = Ok(true),
            Err(_e) => {
                //FIXME - Currently, wasmldr drops the connection unceremoniously, making it look
                // like provisioning failed.  For now, we'll give an "OK" here
                //Err(e.to_string())
                workload_provision_res = Ok(true);
                //workload_provision_res = Err(e.to_string())
            }
        }
    }
    workload_provision_res
}

fn no_cert_run(connect_uri: String) -> Result<reqwest::blocking::Response, reqwest::Error> {
    println!("No cert run");
    reqwest::blocking::Client::builder()
        .https_only(true)
        .danger_accept_invalid_certs(true)
        //.identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .send()
}

fn cert_run(
    certificate: reqwest::Certificate,
    connect_uri: String,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    println!("Cert run");
    reqwest::blocking::Client::builder()
        .https_only(true)
        .add_root_certificate(certificate)
        //.danger_accept_invalid_certs(true)
        //.identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .send()
}

fn no_cert_provisioning(
    connect_uri: String,
    cbor_msg: Vec<u8>,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    println!("No cert check");
    reqwest::blocking::Client::builder()
        .https_only(true)
        .danger_accept_invalid_certs(true)
        //.identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .body(cbor_msg)
        .send()
}

fn cert_provisioning(
    certificate: reqwest::Certificate,
    connect_uri: String,
    cbor_msg: Vec<u8>,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    println!("Cert check");
    reqwest::blocking::Client::builder()
        .https_only(true)
        .add_root_certificate(certificate)
        //.identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .body(cbor_msg)
        .send()
}

fn get_cert_from_https(wasmldr: Wasmldr) -> openssl::x509::X509 {
    //TODO - implement
    //connect to the wasmldr port, get the certificate with
    //SslContextRef from the Sslstream (builder?), return
    // https://serverfault.com/questions/661978/displaying-a-remote-ssl-certificate-details-using-cli-tools ? 
    let mycert: Arc<RwLock<Option<X509>>> = Arc::new(RwLock::new(None));
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();

    builder.set_verify_callback(SslVerifyMode::NONE, {
        let mycert = mycert.clone();
        move |_: bool, chain: &mut X509StoreContextRef| -> bool {
            let cert = chain.current_cert().unwrap().to_owned();
            mycert.write().unwrap().replace(cert);
            true
        }
    });
    let connection_uri = format!("{}:{}", wasmldr.wasmldr_ipaddr, wasmldr.wasmldr_port);
    let connector = builder.build();
    let stream = TcpStream::connect(connection_uri).unwrap();
    let _ = connector.connect(&wasmldr.wasmldr_ipaddr, stream).unwrap();

    let cert = mycert.read().unwrap().clone().unwrap();
    cert
    //TODO - move elsewhere
    //println!("Got cert: {:#?}", &mycert.read().unwrap());

}

fn generate_credentials(wasmldr_addr: &str, pkey: openssl::pkey::PKey<Private>) -> Vec<u8> {
    /*
    //TEST - this should cause failure!//
    let key_length = 2048;
    let key: Rsa<Private> = Rsa::generate(key_length).unwrap();
    let pkey = PKey::from_rsa(key.clone()).unwrap();
    //TEST//
    */

    let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "GB").unwrap();
    x509_name.append_entry_by_text("O", "enarx-test").unwrap();
    x509_name.append_entry_by_text("CN", &wasmldr_addr).unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = openssl::x509::X509::builder().unwrap();
    //from haraldh
    x509_builder.set_issuer_name(&x509_name).unwrap();

    //from haraldh
    //FIXME - this sets certificate creation to daily granularity - need to deal with
    // occasions when we might straddle the date
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let t = t / (60 * 60 * 24) * 60 * 60 * 24;
    let t_end = t + 60 * 60 * 24 * 7;
    if let Err(e) = x509_builder.set_not_before(&Asn1Time::from_unix(t as _).unwrap()) {
        panic!("Problem creating cert {}", e)
    }
    if let Err(e) = x509_builder.set_not_after(&Asn1Time::from_unix(t_end as _).unwrap()) {
        panic!("Problem creating cert {}", e)
    }

    /*
        if let Err(e) = x509_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()) {
            panic!("Problem creating cert {}", e)
        }
        if let Err(e) = x509_builder.set_not_after(&Asn1Time::days_from_now(7).unwrap()) {
            panic!("Problem creating cert {}", e)
        }
    */
    x509_builder.set_subject_name(&x509_name).unwrap();
    x509_builder.set_pubkey(&pkey).unwrap();
    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let certificate = x509_builder.build();

    //println!(
    //    "Current pem array = {}",
    //    std::str::from_utf8(&certificate.to_pem().unwrap()).unwrap()
    //);
    //println!(
    //    "Private key = {}",
    //    std::str::from_utf8(&pkey.private_key_to_pem_pkcs8().unwrap()).unwrap()
    //);

    certificate.to_pem().unwrap()
}

pub fn sev_pre_attest(
    keepmgr_url: String,
    keep: &mut Keep,
    digest: [u8; 32],
) -> Result<CommsComplete, String> {
    //TODO - parameterise key_length?
    let key_length = 2048;
    let key = Rsa::generate(key_length).unwrap();
    let pkey = PKey::from_rsa(key.clone()).unwrap();

    let keep_comms_url = format!("{}/keep/{}", keepmgr_url, keep.kuuid);
    let response = reqwest::blocking::Client::builder()
        .build()
        .unwrap()
        .post(&keep_comms_url)
        .send()
        .expect("Problem connecting to keep");
    let crespbytes = &response.bytes().unwrap();
    println!("Received {} bytes", crespbytes.len());

    //TODO - identify which type of chain?
    //TODO - error handling
    let chain_res: Message = from_reader(&crespbytes[..]).unwrap();
    let chain = match chain_res {
        Message::CertificateChainNaples(chain) => chain,
        Message::CertificateChainRome(chain) => chain,
        _ => panic!("expected certificate chain"),
    };

    //println!("Received chain as first Message");
    let policy = Policy::default();
    let session = Session::try_from(policy).expect("failed to craft policy");

    let start = session.start(chain).expect("failed to start session");
    let start_packet = Message::LaunchStart(start);

    let mut cbor_start_packet = Vec::new();
    into_writer(&start_packet, &mut cbor_start_packet).unwrap();

    /*
    println!(
        "Sending response of {} bytes to {}",
        cbor_start_packet.len(),
        &keepmgr_url
    );
    */
    //println!("Bytes = {:?}", &cbor_start_packet);
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
    //println!("Received second Message of {} bytes", crespbytes.len());

    assert!(matches!(msr, Message::Measurement(_)));
    //println!();

    let secret_packet = if let Message::Measurement(msr) = msr {
        let build: Build = msr.build;

        let measurement: sev::launch::Measurement = msr.measurement;

        //println!("Digest = {:?}", digest);
        //println!("Build = {:?}", build);
        //println!("Measurement = {:?}", msr);
        //println!();

        let session = session
            .verify(&digest, build, measurement)
            .expect("verify failed");

        println!(
            "Keep attestation verification succeeded for Keep {}",
            keep.kuuid
        );
        //FIXME - change to der from pem
        let ct_vec = key.private_key_to_pem().unwrap();
        //println!("ct_vec (private key) = {} bytes", ct_vec.len());
        //println!("ct_vec (private key) = {:?}", &ct_vec);

        let mut cbor_ct = Vec::new();
        into_writer(&ciborium::value::Value::Bytes(ct_vec), &mut cbor_ct)
            .expect("Issues with encoding secret packet");
        //into_writer(&ciborium::value::Value::Bytes(ct_vec), &mut cbor_ct)
        //    .expect("Issues with encoding secret packet");
        //into_writer(&ct_vec, &mut cbor_ct).expect("Issues with encoding secret packet");
        //println!("ct_enc (CBOR encoded key) = {:?}", cbor_ct);
        let secret = session
            .secret(::sev::launch::HeaderFlags::default(), &cbor_ct)
            .expect("gen_secret failed");

        //println!("Sent secret len: {}", cbor_ct.len());
        Message::Secret(Some(secret))
    } else {
        Message::Secret(None)
    };

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

    let crespbytes = &cbor_response.bytes().unwrap();
    let fin: Message = from_reader(&crespbytes[..]).unwrap();

    assert!(matches!(fin, Message::Finish(_)));
    //provide the keep with the public key
    //TODO - this is a side-effect!  Is this acceptable?
    let wasmldr = keep.wasmldr.as_ref().unwrap();
    keep.certificate_as_pem = Some(generate_credentials(&wasmldr.wasmldr_ipaddr, pkey));
    Ok(CommsComplete::Success)
}
