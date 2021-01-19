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

use config::*;
use koine::*;
use std::net::{SocketAddr, ToSocketAddrs};
use uuid::Uuid;
use warp::Filter;

#[tokio::main]
async fn main() {
    let mut settings = config::Config::default();
    settings
        .merge(File::with_name("Keepmgr_config"))
        .unwrap()
        .merge(Environment::with_prefix("client"))
        .unwrap();

    let my_address: String = settings.get("keepmgr_address").unwrap();
    let my_port: u16 = settings.get("keepmgr_port").unwrap();
    println!("Address = {}, port = {}", &my_address, &my_port);
    let full_address = format!("{}:{}", my_address, my_port);

    //initialise to 0.0.0.0 for safety
    let mut socket = SocketAddr::from(([0, 0, 0, 0], my_port));
    //let mut addresses = full_address.to_socket_addrs().unwrap();
    //let mut addresses: SocketAddr;
    let addresses_res = full_address.to_socket_addrs();
    match addresses_res {
        Ok(mut addresses) => {
            println!("Got {} sockaddresss", addresses.len());
            //currently only supporting ipv4 - once we support ipv6,
            // check for Err, instead
            while let Some(sock) = addresses.next() {
                println!("address = {:?}", &sock);
                if sock.is_ipv4() {
                    socket = sock;
                    break;
                }
            }
        }
        Err(e) => {
            panic!("Unable to bind - {}", e);
        }
    }
    assert_ne!(
        socket,
        SocketAddr::from(([0, 0, 0, 0], my_port)),
        "Unable to get address on which to bind"
    );

    let my_info: KeepMgr = KeepMgr {
        address: my_address,
        port: my_port,
    };

    let keepldr_path_root = settings.get("keepldr_path_root").unwrap();

    //find available backends for this host (currently only local - may extend for brokers)
    let available_backends = models::populate_available_backends().await;
    //populate contract list
    let contractlist =
        models::populate_contracts(&available_backends, &my_info, &keepldr_path_root).await;
    //Provide mechanism to find existing Keeps
    let keeplist = models::find_existing_keep_loaders().await;
    //create keepldr connection list
    let keepldrconnlist = models::new_empty_keepldrconnlist();

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
        .and(filters::with_keepldrconnlist(keepldrconnlist.clone()))
        .and_then(filters::new_keep_parse);

    /*
    let keep_comms_by_path = warp::post()
        .and(warp::path("keep"))
        .and(warp::path::param())
        .map(|uuid: Uuid| uuid)
        .and(filters::with_keepldr_path_root(keepldr_path_root))
        .map(|uuid, keepldr_path_root| format!("{}{}", keepldr_path_root, uuid))
        .and(warp::body::aggregate())
        .and_then(filters::keep_by_path);
    */

    let keep_comms_by_path = warp::post()
        .and(warp::path("keep"))
        .and(warp::path::param())
        .map(|uuid: Uuid| uuid)
        //.and(filters::with_keepldrconn_from_uuid(keepldrconnlist, uuid))
        .and(filters::with_keepldrconnlist(keepldrconnlist))
        //.and(filters::with_keepldr_path_root(keepldr_path_root))
        //.map(|uuid, keepldr_path_root| format!("{}{}", keepldr_path_root, uuid))
        .and(warp::body::aggregate())
        .and_then(filters::keep_by_uuid);

    let routes = list_contracts
        .or(new_keep_post)
        //.or(keep_comms_by_uuid)
        .or(keep_comms_by_path)
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
    use koine::threading::lists::*;
    use koine::*;
    use std::path::PathBuf;
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
        //        available_backends: &Vec<Backend>,
        available_backends: &[Backend],
        keepmgr: &KeepMgr,
        keepldr_path_root: &String,
    ) -> ContractList {
        let available_contracts = new_empty_contractlist();
        let mut cl = available_contracts.lock().await;

        //Simple implementation: create a separate contract per available backend
        // - more complex ones are possible (and likely)
        for be in available_backends.iter() {
            let uuid = Uuid::new_v4();
            let pathbuf = format!("{}{}", keepldr_path_root, uuid);
            let new_keepcontract = KeepContract {
                backend: be.clone(),
                keepmgr: keepmgr.clone(),
                uuid: uuid,
                socket_path: PathBuf::from(pathbuf),
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
        //TODO - also remove old sockets (tidy-up)
        new_empty_keeplist()
    }

    pub fn new_empty_contractlist() -> ContractList {
        Arc::new(Mutex::new(Vec::new()))
    }

    pub fn new_empty_keepldrconnlist() -> KeepLdrConnList {
        Arc::new(Mutex::new(Vec::new()))
    }
}

mod filters {
    use ciborium::de::*;
    use ciborium::ser::*;
    use koine::threading::lists::*;
    use koine::*;
    use std::error::Error;
    use std::fmt;
    use std::io::prelude::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::Command;
    use uuid::Uuid;
    use warp::Filter;
    use std::path::PathBuf;


    pub fn systemd_escape(unescaped: String) -> String {
        println!("About to escape string {}", &unescaped);
        let mut escaped = str::replace(&unescaped, "-", "\\x2d");
        escaped = str::replace(&escaped, "/", "-");
        escaped
    }

    pub fn new_keep(contract: KeepContract) -> Keep {
        println!("About to spawn new keep-loader for {} - socket_path = {:?}", contract.uuid, contract.socket_path);
        let service_cmd = format!(
            "enarx-keep-{}@{}.service",
            contract.backend.as_str(),
            systemd_escape(
                contract
                    .socket_path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .unwrap()
            ),
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
            socket_path: contract.socket_path,
            state: LoaderState::Ready,
            wasmldr: None,
            human_readable_info: None,
            certificate_as_pem: None,
        }
    }

    pub fn consume_contract(
        contracts: Vec<KeepContract>,
        consume_contract: &KeepContract,
        repopulate: bool,
    ) -> Option<Vec<KeepContract>> {
        let mut reply_opt = None;
        let mut cl = contracts.clone();
        println!("contract list currently has {} entries", contracts.len());
        for i in 0..cl.len() {
            if consume_contract.uuid == cl[i].uuid {
                let new_keepcontract: Option<KeepContract>;
                println!("Matching contract with uuid = {}", cl[i].uuid);
                if repopulate {
                    let socket_path_str: &str = cl[i].socket_path.to_str().unwrap();
                    let old_uuid = format!("{}", &cl[i].uuid);
                    let keepldr_path_root = socket_path_str.strip_suffix(&old_uuid).unwrap();
                    println!("keepldr_path_root is {}", keepldr_path_root);
                    let new_uuid = Uuid::new_v4();
                    let pathbuf = format!("{}{}", keepldr_path_root, new_uuid);
                    new_keepcontract = Some(KeepContract {
                        backend: cl[i].backend.clone(),
                        keepmgr: cl[i].keepmgr.clone(),
                        uuid: new_uuid,
                        socket_path: PathBuf::from(pathbuf),
                    });
                } else {
                    new_keepcontract = None;
                }
                cl.remove(i);
                match new_keepcontract {
                    Some(kc) => cl.push(kc),
                    None => {}
                }
                //                reply_opt = Some(cl.clone());
                reply_opt = Some(cl);

                break;
            }
        }
        reply_opt
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

    pub fn with_keeplist(
        keeplist: KeepList,
    ) -> impl Filter<Extract = (KeepList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keeplist.clone())
    }

    pub fn with_keepldrconnlist(
        keepldrconnlist: KeepLdrConnList,
    ) -> impl Filter<Extract = (KeepLdrConnList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keepldrconnlist.clone())
    }

    pub fn with_contractlist(
        contractlist: ContractList,
    ) -> impl Filter<Extract = (ContractList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || contractlist.clone())
    }

    pub fn with_keepldr_path_root(
        path_root: String,
    ) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || path_root.clone())
    }

    //FIXME - needs KeepLdrConnection usage addition
    pub async fn keep_by_uuid<B>(
        uuid: Uuid,
        keepldrconnlist: KeepLdrConnList,
        bytes: B,
    ) -> Result<impl warp::Reply, warp::Rejection>
    where
        B: hyper::body::Buf,
    {
        //this function sets up a Unix domain connection to the Keep, and then
        // proxy communications between the client and the Keep.  If no connection
        // can be set up, we return "CommsComplete::Failure"
        let mbytes: &[u8] = bytes.bytes();
        let msg_bytes = mbytes.as_ref();
        //let msg: String = from_reader(&msg_bytes[..]).unwrap();
        //println!("Message received was: {}", msg);
        let klcl = keepldrconnlist.lock().await;

        println!(
            "Received communications request for comms with Keep {} of {} bytes",
            &uuid,
            msg_bytes.len(),
        );

        let mut klstream_result: Option<&UnixStream> = None;
        for keepldrconn in klcl.iter() {
            if keepldrconn.kuuid == uuid {
                klstream_result = keepldrconn.keepldrstream.as_ref();
                break;
            }
            //FALL-THROUGH
            klstream_result = None;
        }

        match klstream_result {
            Some(mut keepldr_stream) => {
                //NOTE - UNTESTED!!!
                //println!("Sending {} bytes to keepldr", msg_bytes.len());
                keepldr_stream
                    .write(msg_bytes)
                    .expect("Unable to write to stream");
                //let cbor_val_res = ciborium::de::from_reader(keepldr_stream);
                let cbor_val_res: Result<ciborium::value::Value, _> =
                    ciborium::de::from_reader(keepldr_stream);
                match cbor_val_res {
                    //match ciborium::de::from_reader(keepldr_stream) {
                    Ok(cbor_val) => {
                        //       println!("Received CBOR value {:?}", cbor_val);
                        let mut cbor_reply_body = Vec::new();
                        into_writer(&cbor_val, &mut cbor_reply_body).unwrap();
                        println!("Sending {} bytes to client", cbor_reply_body.len());
                        Ok(cbor_reply_body)
                    }
                    Err(e) => {
                        //if nothing is returned, we return "CommsComplete: Success",
                        // as we managed to connect - we can assume no comms required by
                        // this keepldr
                        println!("No or unparseable reply from keepldr, {}", e);
                        let comms_complete = CommsComplete::Success;
                        let mut cbor_reply_body = Vec::new();
                        into_writer(&comms_complete, &mut cbor_reply_body).unwrap();
                        Ok(cbor_reply_body)
                    }
                }

                /*
                let mut response_buf = [0; 65556];
                let mut count = keepldr_stream.read(&mut response_buf).unwrap();
                println!("Received {} bytes from keepldr", count);

                let mut response: Vec<u8> = Vec::new();
                response.append(&mut response_buf[..count].to_vec());
                while count > 0 {
                    //our reply should already be CBOR encoded,
                    // so send it straight back to the client
                    println!("Received {} bytes from keepldr", count);
                    count = keepldr_stream.read(&mut response_buf).unwrap();
                    response.append(&mut response_buf[..count].to_vec());
                }
                */
            }
            None => {
                let comms_complete = CommsComplete::Failure;
                let mut cbor_reply_body = Vec::new();
                into_writer(&comms_complete, &mut cbor_reply_body).unwrap();
                Ok(cbor_reply_body)
            }
        }
    }

    /*
        //TODO - add keepldrconnection here
        pub async fn keep_by_path<B>(
            path_string: String,
            bytes: B,
        ) -> Result<impl warp::Reply, warp::Rejection>
        where
            B: hyper::body::Buf,
        {
            //this function sets up a Unix domain connection to the Keep, and then
            // proxy communications between the client and the Keep.  If no connection
            // can be set up, we return "CommsComplete::Failure"
            let mbytes: &[u8] = bytes.bytes();
            let msg_bytes = mbytes.as_ref();
            //let msg: String = from_reader(&msg_bytes[..]).unwrap();
            //println!("Message received was: {}", msg);

            println!(
                "Received communications request for comms with Keep, path to socket = {}",
                path_string
            );

            let keepldr_stream_result = UnixStream::connect(path_string);
            match keepldr_stream_result {
                Ok(mut keepldr_stream) => {
                    //NOTE - UNTESTED!!!
                    //data should already be CBOR encoded, so send on to keepldr
                    keepldr_stream
                        .write(msg_bytes)
                        .expect("Unable to write to stream");
                    //TODO - what's an appropriate buffer size?
                    let mut response_buf = [0; 65556];
                    let count = keepldr_stream.read(&mut response_buf).unwrap();

                    if count > 0 {
                        //our reply should already be CBOR encoded,
                        // so send it straight back to the client
                        let response = response_buf[..count].to_vec();
                        Ok(response)
                    } else {
                        //if nothing is returned, we return "CommsComplete: Success",
                        // as we managed to connect - we can assume no comms required by
                        // this keepldr
                        let comms_complete = CommsComplete::Success;
                        let mut cbor_reply_body = Vec::new();
                        into_writer(&comms_complete, &mut cbor_reply_body).unwrap();
                        Ok(cbor_reply_body)
                    }
                }
                Err(_) => {
                    let comms_complete = CommsComplete::Failure;
                    let mut cbor_reply_body = Vec::new();
                    into_writer(&comms_complete, &mut cbor_reply_body).unwrap();
                    Ok(cbor_reply_body)
                }
            }
        }
    */
    pub async fn list_contracts(
        available_contracts: ContractList,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        println!("About to serve contractlist (from list_contracts())");
        let mut cl = available_contracts.lock().await;
        let cl = &mut *cl;

        let conl: Vec<KeepContract> = cl.to_vec();

        println!("Found {} contracts", cl.len());
        println!("KeepContract[0] Uuid = {:?}", cl[0].uuid);
        println!("KeepContract[0] = {:?}", cl[0]);
        println!("KeepContract[1] = {:?}", cl[1]);
        let mut cbor_reply_body = Vec::new();
        println!("cbor_reply_body len = {}", &cbor_reply_body.len());
        //        into_writer(&cl, &mut cbor_reply_body).unwrap();
        into_writer(&conl, &mut cbor_reply_body).unwrap();
        println!("cbor_reply_body len now = {}", &cbor_reply_body.len());
        //println!("bytes = {:02x?}", &cbor_reply_body);

        Ok(cbor_reply_body)
    }

    pub async fn new_keep_parse<B>(
        bytes: B,
        available_contracts: ContractList,
        keeplist: KeepList,
        keepldrconnlist: KeepLdrConnList,
    ) -> Result<impl warp::Reply, warp::Rejection>
    where
        B: hyper::body::Buf,
    {
        //retrieve a Vector of u8 from the received body
        let kbytes: &[u8] = bytes.bytes();
        println!("new_keep_parse received {} bytes", kbytes.len());
        println!("kbytes = {:02x?}", &kbytes);
        let kcontract_bytes = kbytes.as_ref();

        let keepcontract: KeepContract = from_reader(&kcontract_bytes[..]).unwrap();
        println!("bytes = {:02x?}", &keepcontract);

        //deserialise the Vector into a KeepContract (and handle errors)
        println!("\n\nnew-keep ...");
        //TODO - we need to get the listen address from the Keep later in the process
        //TODO - change to see whether there's a matching contract, rather than just
        // a backend - by consumption
        let mut kcl = available_contracts.lock().await;
        let new_contracts_list: Option<Vec<KeepContract>> =
            consume_contract(kcl.clone(), &keepcontract, true);
        match new_contracts_list {
            Some(ncl) => {
                //a returned contract list means that we were successful
                println!(
                    "Received a request for an available Contract uuid= {:?}",
                    keepcontract.uuid
                );
                let mut kll = keeplist.lock().await;
                let mut klcl = keepldrconnlist.lock().await;
                println!(
                    "Keeplist currently has {} entries, about to add {}",
                    kll.len(),
                    keepcontract.uuid,
                );
                let new_keep = new_keep(keepcontract);
                //in the case of an sev keep, immediately bind to a Unix socket and await a connection
                println!("About to bind to {:?}", &new_keep.socket_path);
                let keepldrconn: KeepLdrConnection;
                if new_keep.backend == Backend::Sev {
                    let listener = UnixListener::bind(&new_keep.socket_path).unwrap();
                    let keepldr_stream = match listener.accept() {
                        Ok((socket, _addr)) => socket,
                        Err(e) => {
                            //better error handling (with time-outs, etc.) here.
                            panic!("Failed to get a connection - {}", e);
                        }
                    };
                    keepldrconn = KeepLdrConnection {
                        kuuid: new_keep.kuuid,
                        keepldrstream: Some(keepldr_stream),
                    };
                } else {
                    keepldrconn = KeepLdrConnection {
                        kuuid: new_keep.kuuid,
                        keepldrstream: None,
                    }
                }
                klcl.push(keepldrconn);
                // *** replace klcl?
                kll.push(new_keep.clone());
                //replace old list of available contracts with updated one
                *kcl = ncl;
                //available_contracts = Arc::new(Mutex::new(Vec::new())).push(ncl);
                //let cbor_reply_body: Vec<u8> = to_vec(&new_keep).unwrap();
                let mut cbor_reply_body = Vec::new();
                into_writer(&new_keep, &mut cbor_reply_body).unwrap();
                Ok(cbor_reply_body)
            }
            None => {
                println!("Unsupported contract requested");
                let lcbore = LocalCborErr::new("No such contract");
                Err(warp::reject::custom(lcbore))
            }
        }
    }
}
