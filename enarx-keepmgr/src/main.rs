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
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), BIND_PORT);

    //find available backends for this host (currently only local - may extend?)
    let available_backends = models::populate_available_backends().await;

    //Provide mechanism to find existing Keeps
    let keeplist = models::find_existing_keep_loaders().await;

    let declare = warp::any().map(|| {
        format!(
            "Protocol_name = {}\nProtocol_version = {}",
            PROTO_NAME, PROTO_VERSION
        )
    });

    let new_keep_post = warp::post()
        .and(warp::path("new_keep"))
        //  .and(warp::body::stream())
        .and(warp::body::bytes())
        .and(filters::with_available_backends(available_backends))
        .and(filters::with_keeplist(keeplist))
        .and_then(filters::new_keep_parse);

    let routes = new_keep_post.or(declare);
    println!(
        "Starting server on {}, {} v{}",
        BIND_PORT, PROTO_NAME, PROTO_VERSION
    );
    warp::serve(routes)
        .tls()
        .cert_path("key-material/server.crt")
        .key_path("key-material/server.key")
        .run(socket)
        .await;
}

mod models {
    use koine::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub async fn populate_available_backends() -> Vec<Backend> {
        let mut available_backends = Vec::new();
        //add backends - assume both KVM and Nil backends ("nil") are available
        //TODO - add checks for SEV and SGX
        available_backends.push(Backend::Nil);
        available_backends.push(Backend::Kvm);
        available_backends
    }

    pub type KeepList = Arc<Mutex<Vec<koine::Keep>>>;

    pub fn new_empty_keeplist() -> KeepList {
        Arc::new(Mutex::new(Vec::new()))
    }
    pub async fn find_existing_keep_loaders() -> KeepList {
        println!("Looking for existing keep-loaders in /tmp");
        //TODO - implement (scheme required)
        new_empty_keeplist()
    }
}

mod filters {
    //    use bytes::buf::Buf;
    //    use bytes::Bytes;
    use koine::*;
    use serde_cbor::*;
    use std::convert::Infallible;
    use std::process::Command;
    use uuid::Uuid;
    use warp::{http::StatusCode, reject::Reject, Filter, Rejection, Reply, Stream};

    // -------
    struct Invalid;
    impl Reject for Invalid {}

    fn validated_body(
        bytes: warp::hyper::body::Bytes,
    ) -> impl Filter<Extract = (warp::hyper::body::Bytes,), Error = Rejection> + Copy {
        (|bytes: Bytes| async move {
            if bytes.slice(..) {
                Ok(bytes.slice(..))
            } else {
                Err(warp::reject::custom(Invalid))
            }
        })
    }

    async fn report_invalid(r: Rejection) -> Result<impl Reply, Infallible> {
        let reply = warp::reply::reply();

        if let Some(Invalid) = r.find() {
            Ok(warp::reply::with_status(reply, StatusCode::BAD_REQUEST))
        } else {
            // Do better error handling here
            Ok(warp::reply::with_status(
                reply,
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }

    // -------

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

    pub fn new_keep(backend: Backend) -> Keep {
        let new_kuuid = Uuid::new_v4();
        println!("About to spawn new keep-loader");
        let service_cmd = format!("enarx-keep-{}@{}.service", backend.as_str(), new_kuuid);
        println!("service_cmd = {}", new_kuuid);
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

    pub async fn new_keep_parse(
        //        cbor_stream: warp::hyper::body::Bytes,
        cbor_stream: &[u8],

        available_backends: Vec<Backend>,
        keeplist: KeepList,
        //    ) -> Result<impl warp::Reply, Infallible> {
    ) -> Result<impl warp::Reply> {
        let undefined = UndefinedReply {
            text: String::from("undefined"),
        };
        //FIXME - we need a cbor-reply
        let mut json_reply = warp::reply::json(&undefined);

        //        let mut it = Deserializer::from_slice(&data[..]).into_iter::<Value>();
        //let keepcontract = Deserializer::from_reader(cbor_stream).into_iter::<KeepContract>();
        let keepcontract: KeepContract = de::from_slice(&cbor_stream).unwrap();

        //assume unsupported to start
        let mut supported: bool = false;
        println!("new-keep ...");

        let keeparch = keepcontract.backend;
        //TODO - we need to get the listen address from the Keep later in the process
        //TODO - check supported
        /*
        if available_backends.iter().any(|backend| backend == keeparch) {
            supported = true;
        }*/

        if supported {
            let mut kll = keeplist.lock().await;
            let new_keep = new_keep(keeparch);
            println!(
                "Keeplist currently has {} entries, about to add {}",
                kll.len(),
                new_keep.kuuid,
            );
            //add this new new keep to the list
            kll.push(new_keep.clone());
            json_reply = warp::reply::json(&new_keep);
        //TODO - deal with attestation via "stream"
        } else {
            json_reply = warp::reply::json(&"Unsupported backend".to_string());
        }
        //FIXME - need a cbor reply!
        Ok(json_reply)
    }
    /*
        //TODO - break this into different methods
        pub async fn old_keeps_parse(
            cbor_response: Vec<u8>,
            available_backends: Vec<Backend>,
            keeplist: KeepList,
        ) -> Result<impl warp::Reply, Infallible> {
            let undefined = UndefinedReply {
                text: String::from("undefined"),
            };
            //FIXME - we need a cbor-reply
            let mut json_reply = warp::reply::json(&undefined);

            //FIXME - have different filters (based on path) - then you know what you have
            match command_group.get(KEEP_COMMAND).unwrap().as_str() {
                //TODO - list available IP addresses
                "list-keep-types" => json_reply = warp::reply::json(&available_backends),
                "new-keep" => {
                    //assume unsupported to start
                    let mut supported: bool = false;
                    println!("new-keep ...");
                    //FIXME - not a String!
                    let keeparch = command_group.get(KEEP_ARCH).unwrap().as_str();
                    //TODO - we need to get the listen address from the Keep later in the process

                    if available_backends.iter().any(|backend| backend == keeparch) {
                        supported = true;
                    }

                    if supported {
                        let mut kll = keeplist.lock().await;
                        let new_keep = new_keep(keeparch);
                        println!(
                            "Keeplist currently has {} entries, about to add {}",
                            kll.len(),
                            new_keep.kuuid,
                        );
                        //add this new new keep to the list
                        kll.push(new_keep.clone());
                        json_reply = warp::reply::json(&new_keep);
                    //TODO - deal with attestation via "stream"
                    } else {
                        json_reply = warp::reply::json(&"Unsupported backend".to_string());
                    }
                }
                "list-keeps" => {
                    //update list
                    let kll = keeplist.lock().await;

                    let kllvec: Vec<Keep> = kll.clone().into_iter().collect();
                    for keep in &kllvec {
                        println!("Keep kuuid {}", keep.kuuid);
                    }
                    let json_keepvec = KeepVec { klvec: kllvec };
                    json_reply = warp::reply::json(&json_keepvec);
                }
                &_ => {}
            }
            println!(
                "Received a {:?} command",
                command_group.get(KEEP_COMMAND).unwrap()
            );
            Ok(json_reply)
        }
    */
}
