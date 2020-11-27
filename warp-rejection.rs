use serde::Deserialize;
use std::{convert::Infallible, net::IpAddr};
use warp::{filters::BoxedFilter, http::StatusCode, reject::Reject, Filter, Rejection, Reply};

fn route1() -> BoxedFilter<(String, ParamType)> {
    warp::get()
        .and(warp::path::param())
        .and(validated_query())
        .and(warp::path::end())
        .boxed()
}

#[derive(Debug)]
struct Invalid;
impl Reject for Invalid {}

fn validated_query() -> impl Filter<Extract = (ParamType,), Error = Rejection> + Copy {
    warp::filters::query::query().and_then(|param: ParamType| async move {
        if param.valid {
            Ok(param)
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

async fn handler1(
    _query: String,
    _param: ParamType,
    _dependency: DependencyType,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::reply())
}

struct DependencyType;

#[derive(Deserialize)]
struct ParamType {
    valid: bool,
}

#[tokio::main]
async fn main() {
    let api = route1()
        .and(warp::any().map(move || DependencyType))
        .and_then(handler1)
        .recover(report_invalid);

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let port = 8888;
    warp::serve(api).run((ip, port)).await;
}
