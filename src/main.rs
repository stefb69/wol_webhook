use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode, Server};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use base64::decode;
use std::env;

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

struct AppState {
    machine_status: Mutex<HashMap<String, String>>,
    broadcast_ip: String,
    broadcast_port: u16,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

async fn handle_request(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    let get_regex = Regex::new(r"^/(?P<MAC>([\da-f]{2}[:-]){5}[\da-f]{2})[/]?$").unwrap();
    let post_regex = Regex::new(r"^/(?P<MAC>([\da-f]{2}[:-]){5}[\da-f]{2})/\?op=(?P<OP>(start|stop))$").unwrap();

    let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());

    if let Some(auth) = &state.token {
        if auth_header != Some(auth) {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized!\n"))
                .unwrap());
        }
    } else if let (Some(username), Some(password)) = (&state.username, &state.password) {
        if let Some(auth) = auth_header {
            let cred = decode(auth.split_whitespace().nth(1).unwrap_or("")).unwrap();
            let cred_str = String::from_utf8(cred).unwrap();
            if cred_str != format!("{}:{}", username, password) {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("Unauthorized!\n"))
                    .unwrap());
            }
        } else {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized!\n"))
                .unwrap());
        }
    }

    if req.method() == hyper::Method::GET {
        if let Some(caps) = get_regex.captures(req.uri().path()) {
            let mac = caps.name("MAC").unwrap().as_str().to_string();
            let status = {
                let machine_status = state.machine_status.lock().unwrap();
                machine_status.get(&mac).cloned().unwrap_or_else(|| "unknown".to_string())
            };

            let response = StatusResponse { status };
            let body = serde_json::to_string(&response).unwrap() + "\n";
            Ok(Response::new(Body::from(body)))
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Unknown path!\n"))
                .unwrap())
        }
    } else if req.method() == hyper::Method::POST {
        if let Some(caps) = post_regex.captures(req.uri().path()) {
            let mac = caps.name("MAC").unwrap().as_str().to_string();
            let op = caps.name("OP").unwrap().as_str();

            if op == "start" {
                let mac_address = mac.replace(":", "").replace("-", "");
                let mut packet = vec![0xFF; 6];
                for _ in 0..16 {
                    packet.extend_from_slice(&hex::decode(&mac_address).unwrap());
                }

                let broadcast_addr = format!("{}:{}", state.broadcast_ip, state.broadcast_port);
                let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                socket.set_broadcast(true).unwrap();
                socket.send_to(&packet, &broadcast_addr).await.unwrap();

                {
                    let mut machine_status = state.machine_status.lock().unwrap();
                    machine_status.insert(mac, "running".to_string());
                }

                Ok(Response::new(Body::from("WoL packet sent!\n")))
            } else if op == "stop" {
                {
                    let mut machine_status = state.machine_status.lock().unwrap();
                    machine_status.insert(mac, "stopped".to_string());
                }

                Ok(Response::new(Body::from("User has shutdown the system!\n")))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Unknown operation!\n"))
                    .unwrap())
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Unknown path!\n"))
                .unwrap())
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method not allowed!\n"))
            .unwrap())
    }
}

#[tokio::main]
async fn main() {
    let broadcast_ip = env::args().nth(1).unwrap_or("255.255.255.255".to_string());
    let broadcast_port: u16 = env::args().nth(2).unwrap_or("9".to_string()).parse().unwrap();
    let port: u16 = env::args().nth(3).unwrap_or("8080".to_string()).parse().unwrap();
    let username = env::args().nth(4);
    let password = env::args().nth(5);
    let token = env::args().nth(6);

    let state = Arc::new(AppState {
        machine_status: Mutex::new(HashMap::new()),
        broadcast_ip,
        broadcast_port,
        username,
        password,
        token,
    });

    let make_svc = make_service_fn(move |_| {
        let state = state.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| handle_request(req, state.clone()))) }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening for requests on port {}", port);

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}
