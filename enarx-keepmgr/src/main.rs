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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::Filter;

#[tokio::main]
async fn main() {
    //TODO - remove hard-coded values - will require certificate changes/generation
    let my_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let socket = SocketAddr::new(my_addr, BIND_PORT);

    let my_info: KeepMgr = KeepMgr {
        ipaddr: my_addr,
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

    let list_contracts = warp::post()
        .and(warp::path("contracts"))
        .and(filters::with_contractlist(contractlist))
        .and_then(filters::list_contracts);

    let new_keep_post = warp::post()
        .and(warp::path("new_keep"))
        .and(warp::body::aggregate())
        .and(filters::with_available_backends(available_backends.clone()))
        .and(filters::with_keeplist(keeplist))
        .and_then(filters::new_keep_parse);

    let routes = list_contracts.or(new_keep_post).or(declare);
    //    let routes = list_contracts.or(declare);
    println!(
        "Starting server on {}, {} v{}",
        BIND_PORT, PROTO_NAME, PROTO_VERSION
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
    use koine::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    pub async fn populate_available_backends() -> Vec<Backend> {
        let mut available_backends = Vec::new();
        //add backends - assume both KVM and Nil backends ("nil") are available
        //TODO - add checks for SEV and SGX
        available_backends.push(Backend::Nil);
        available_backends.push(Backend::Kvm);
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

    pub async fn consume_contract(
        contracts: ContractList,
        consume_contract: KeepContract,
    ) -> Option<Uuid> {
        let reply_opt = None;
        let mut cl = contracts.lock().await;
        println!("contract list currently has {} entries", cl.len());
        for i in 0..cl.len() {
            if consume_contract.uuid == cl[i].uuid {
                cl.remove(i);
                Some(consume_contract.uuid);
            }
        }

        reply_opt
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

    pub fn new_keep(backend: Backend) -> Keep {
        //TODO - consume uuid from contract (this should be passed instead of Backend),
        // then repopulate
        let new_kuuid = Uuid::new_v4();
        println!("About to spawn new keep-loader");
        let service_cmd = format!("enarx-keep-{}@{}.service", backend.as_str(), new_kuuid);
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
            backend.as_str(),
            new_kuuid
        );

        Keep {
            backend: backend,
            kuuid: new_kuuid,
            state: LoaderState::Ready,
            wasmldr: None,
            human_readable_info: None,
        }
    }

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
        available_backends: Vec<Backend>,
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
            Ok(k) => {
                keepcontract = k;
                //assume unsupported to start
                let mut supported: bool = false;
                println!("\nnew-keep ...");

                let keeparch = keepcontract.backend;
                //TODO - we need to get the listen address from the Keep later in the process
                //TODO - change to see whether there's a matching contract, rather than just
                // a backend
                if available_backends // <- available_contracts
                    .iter()
                    .any(|backend| backend == &keeparch)
                {
                    supported = true;
                    println!(
                        "Received a request for a supported Keep ({})",
                        keeparch.as_str()
                    );
                } else {
                    println!("Unsupported backend requested");
                }

                if supported {
                    //TODO - <- change to check on consumption (Option(uuid) == good, None == bad)
                    let mut kll = keeplist.lock().await;
                    let new_keep = new_keep(keeparch); //<- TODO - contract, not keeparch
                    println!(
                        "Keeplist currently has {} entries, about to add {}",
                        kll.len(),
                        new_keep.kuuid,
                    );
                    //TODO - consume this from the contract list

                    //add this new new keep to the list
                    kll.push(new_keep.clone());

                    //TODO - repopulate (with one of the same type?)
                    let cbor_reply_body: Vec<u8> = to_vec(&new_keep).unwrap();
                    let cbor_reply: CborReply = CborReply {
                        msg: cbor_reply_body,
                    };
                    Ok(cbor_reply)
                } else {
                    let lcbore = LocalCborErr::new("Unsupported backend");
                    Err(warp::reject::custom(lcbore))
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
