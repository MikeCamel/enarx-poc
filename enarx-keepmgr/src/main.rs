// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx-keepmgr` executable which creates and
//! coordinates enarx-keepldr instances
//!
//! # Build
//!
//!     $ git clone https://github.com/enarx/enarx-keepmgr
//!     $ cd enarx-keepmgr
//!     $ cargo build
//!
//! # Run Tests
//!
//!     $ cargo run enarx-keepmgr-tester
//!

#![deny(clippy::all)]

use koine::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use uuid::Uuid;
use warp::Filter;

#[tokio::main]
async fn main() {
    //TODO - remove hard-coded values - will require certificate changes/generation
    //    let my_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    //    let my_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202));
    let my_address = "192.168.1.202".to_string();
    let full_address = format!("{}:{}", my_address, BIND_PORT);
    let mut socket = full_address.to_socket_addrs().unwrap().next().unwrap();
    //let socket = SocketAddr::new(my_address, BIND_PORT);

    let my_info: KeepMgr = KeepMgr {
        address: my_address,
        //        ipaddr: my_addr,
        port: BIND_PORT,
    };

    //find available backends for this host (currently only local - may extend?)
    let available_backends = models::populate_available_backends().await;
    //populate contract list
    let contractlist = models::populate_contracts(&available_backends, &my_info).await;
    //Provide mechanism to find existing Keeps
    let keeplist = models::find_existing_keep_loaders().await;

    let declare = warp::any().map(|| {
        format!(
            "Protocol_name = {}\nProtocol_version = {}",
            PROTO_NAME, PROTO_VERSION
        )
    });

    //list available contracts
    let list_contracts = warp::post()
        .and(warp::path("contracts"))
        .and(filters::with_contractlist(contractlist.clone()))
        .and_then(filters::list_contracts);

    //manage new keep requests
    let new_keep_post = warp::post()
        .and(warp::path("new_keep"))
        .and(warp::body::aggregate())
        .and(filters::with_contractlist(contractlist.clone()))
        .and(filters::with_keeplist(keeplist.clone()))
        .and_then(filters::new_keep_parse);

    //manage communications from clients to keeps, by uuid
    //FIXME - not working properly at the moment
    let keep_comms_by_uuid = warp::post()
        .and(warp::path("keep"))
        .and(warp::path::param())
        .map(|uuid: Uuid| uuid)
        .and_then(filters::keep_by_uuid);

    let routes = list_contracts
        .or(new_keep_post)
        .or(keep_comms_by_uuid)
        .or(declare);
    println!(
        "Starting server on {}, {} v{}",
        &socket, PROTO_NAME, PROTO_VERSION
    );
    warp::serve(routes)
        //removing TLS for now due to certificate issues
        //.tls()
        //.cert_path("key-material/server.crt")
        //.key_path("key-material/server.key")
        .run(socket)
        .await;
}

mod models {
    use glob::glob;
    use koine::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    pub async fn populate_available_backends() -> Vec<Backend> {
        let mut available_backends = Vec::new();
        //add backends - assume both KVM and Nil backends ("nil") are available
        match glob(Backend::file_match(&Backend::Nil)) {
            Ok(f) => {
                if f.into_iter().count() > 0 {
                    available_backends.push(Backend::Nil);
                }
            }
            Err(_) => {
                println!("nil not supported");
            }
        }
        match glob(Backend::file_match(&Backend::Kvm)) {
            Ok(f) => {
                if f.into_iter().count() > 0 {
                    available_backends.push(Backend::Kvm);
                    match glob(Backend::file_match(&Backend::Sev)) {
                        Ok(g) => {
                            if g.into_iter().count() > 0 {
                                available_backends.push(Backend::Sev);
                            }
                        }
                        Err(_) => {
                            println!("sev not supported");
                        }
                    }
                }
            }
            Err(_) => {
                println!("kvm not supported");
            }
        }
        match glob(Backend::file_match(&Backend::Sgx)) {
            Ok(f) => {
                if f.into_iter().count() > 0 {
                    available_backends.push(Backend::Sgx);
                }
            }
            Err(_) => println!("sgx is not supported"),
        }
        available_backends
    }

    pub async fn populate_contracts(
        available_backends: &Vec<Backend>,
        keepmgr: &KeepMgr,
    ) -> ContractList {
        let available_contracts = new_empty_contractlist();
        let mut cl = available_contracts.lock().await;

        //Simple implementation: create a separate contract per available backend
        // - more complex ones are possible (and likely)
        for be in available_backends.iter() {
            let new_keepcontract = KeepContract {
                backend: be.clone(),
                keepmgr: keepmgr.clone(),
                uuid: Uuid::new_v4(),
            };
            println!("Populating contract list with backend {}", be.as_str());
            cl.push(new_keepcontract.clone());
        }
        available_contracts.clone()
    }

    pub fn new_empty_keeplist() -> KeepList {
        Arc::new(Mutex::new(Vec::new()))
    }
    pub async fn find_existing_keep_loaders() -> KeepList {
        println!("Looking for existing keep-loaders in /tmp");
        //TODO - implement (scheme required)
        new_empty_keeplist()
    }

    pub fn new_empty_contractlist() -> ContractList {
        Arc::new(Mutex::new(Vec::new()))
    }
}

mod filters {
    use http::response::*;
    use koine::*;
    use serde_cbor::{de, to_vec};
    use std::error::Error;
    use std::fmt;
    use std::process::Command;
    use uuid::Uuid;
    use warp::Filter;

    //pub fn new_keep(backend: Backend) -> Keep {
    pub fn new_keep(contract: KeepContract) -> Keep {
        //TODO - consume uuid from contract (this should be passed instead of Backend),
        // then repopulate
        //        let kuuid = contract.uuid;
        println!("About to spawn new keep-loader");
        let service_cmd = format!(
            "enarx-keep-{}@{}.service",
            contract.backend.as_str(),
            contract.uuid
        );
        println!("service_cmd = {}", service_cmd);
        let _child = Command::new("systemctl")
            .arg("--user")
            .arg("start")
            .arg(service_cmd)
            .output()
            .expect("failed to execute child");

        println!("Spawned new keep-loader");
        println!(
            "Got this far with backend = {}, new_kuuid = {}",
            contract.backend.as_str(),
            contract.uuid
        );

        Keep {
            backend: contract.backend,
            kuuid: contract.uuid,
            state: LoaderState::Ready,
            wasmldr: None,
            human_readable_info: None,
        }
    }

    pub fn consume_contract(
        contracts: Vec<KeepContract>,
        consume_contract: &KeepContract,
    ) -> Option<Vec<KeepContract>> {
        let mut reply_opt = None;
        let mut cl = contracts.clone();
        println!("contract list currently has {} entries", contracts.len());
        for i in 0..cl.len() {
            if consume_contract.uuid == cl[i].uuid {
                println!("Matching contract with uuid = {}", cl[i].uuid);
                cl.remove(i);
                reply_opt = Some(cl.clone());
                break;
            }
        }
        reply_opt
    }
    //these should be taken from koine, but for some reason, are not
    //FIXME! ----------
    #[derive(Debug)]
    struct CborReply {
        pub msg: Vec<u8>,
    }

    impl warp::reply::Reply for CborReply {
        fn into_response(self) -> warp::reply::Response {
            Response::new(self.msg.into())
        }
    }

    #[derive(Debug)]
    struct LocalCborErr {
        details: String,
    }

    impl LocalCborErr {
        fn new(msg: &str) -> LocalCborErr {
            LocalCborErr {
                details: msg.to_string(),
            }
        }
    }

    impl fmt::Display for LocalCborErr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.details)
        }
    }

    impl Error for LocalCborErr {
        fn description(&self) -> &str {
            &self.details
        }
    }

    impl warp::reject::Reject for LocalCborErr {}

    //FIXME! ----------

    pub fn with_available_backends(
        available_backends: Vec<Backend>,
    ) -> impl Filter<Extract = (Vec<Backend>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || available_backends.clone())
    }

    pub fn with_keeplist(
        keeplist: KeepList,
    ) -> impl Filter<Extract = (KeepList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keeplist.clone())
    }

    pub fn with_contractlist(
        contractlist: ContractList,
    ) -> impl Filter<Extract = (ContractList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || contractlist.clone())
    }

    pub async fn keep_by_uuid(uuid: Uuid) -> Result<impl warp::Reply, warp::Rejection> {
        //TODO - implement
        //
        //this function will set up a Unix domain connection to the Keep, and then
        // proxy communications between the client and the Keep.  For now, we return
        // a successful "comms_complete" message to the client
        //
        println!(
            "Received communications request for comms with Keep, uuid = {}",
            uuid
        );
        let comms_complete = CommsComplete::Success;

        let cbor_reply_body: Vec<u8> = to_vec(&comms_complete).unwrap();
        let cbor_reply: CborReply = CborReply {
            msg: cbor_reply_body,
        };
        Ok(cbor_reply)
    }

    pub async fn list_contracts(
        available_contracts: ContractList,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        println!("About to serve contractlist (from list_contracts())");
        let mut cl = available_contracts.lock().await;
        let cl = &mut *cl;
        println!("Found {} contracts", cl.len());
        let cbor_reply_body: Vec<u8> = to_vec(&cl).unwrap();
        let cbor_reply: CborReply = CborReply {
            msg: cbor_reply_body,
        };
        Ok(cbor_reply)
    }

    pub async fn new_keep_parse<B>(
        bytes: B,
        available_contracts: ContractList,
        keeplist: KeepList,
    ) -> Result<impl warp::Reply, warp::Rejection>
    where
        B: hyper::body::Buf,
    {
        //retrieve a Vector of u8 from the received body
        let mut bytesvec: Vec<u8> = Vec::new();
        bytesvec.extend_from_slice(bytes.bytes());

        //deserialise the Vector into a KeepContract (and handle errors)
        let keepcontract: KeepContract;
        match de::from_slice(&bytesvec) {
            Ok(kc) => {
                keepcontract = kc;
                println!("\nnew-keep ...");
                //let mut cl = available_contracts.lock().await;
                //TODO - we need to get the listen address from the Keep later in the process
                //TODO - change to see whether there's a matching contract, rather than just
                // a backend - by consumption
                let mut kcl = available_contracts.lock().await;
                let new_contracts_list: Option<Vec<KeepContract>> =
                    consume_contract(kcl.clone(), &keepcontract);
                match new_contracts_list {
                    Some(ncl) => {
                        //a returned contract list means that we were successful
                        println!(
                            "Received a request for an available Contract uuid= {:?}",
                            keepcontract.uuid
                        );
                        let mut kll = keeplist.lock().await;
                        println!(
                            "Keeplist currently has {} entries, about to add {}",
                            kll.len(),
                            keepcontract.uuid,
                        );
                        let new_keep = new_keep(keepcontract);
                        kll.push(new_keep.clone());
                        //replace old list of available contracts with updated one
                        *kcl = ncl;
                        //available_contracts = Arc::new(Mutex::new(Vec::new())).push(ncl);
                        //TODO - repopulate (with one of the same type?)
                        let cbor_reply_body: Vec<u8> = to_vec(&new_keep).unwrap();
                        let cbor_reply: CborReply = CborReply {
                            msg: cbor_reply_body,
                        };
                        Ok(cbor_reply)
                    }
                    None => {
                        println!("Unsupported contract requested");
                        let lcbore = LocalCborErr::new("No such contract");
                        Err(warp::reject::custom(lcbore))
                    }
                }
            }
            Err(e) => {
                let lcbore = LocalCborErr {
                    details: e.to_string(),
                };
                Err(warp::reject::custom(lcbore))
            }
        }
    }
}
