use warp::Filter;
use std::net::UdpSocket;
use serde::{Deserialize, Serialize};
use log::{info, error};
use simplelog::{Config, SimpleLogger, LevelFilter};

#[derive(Deserialize, Serialize)]
struct WebhookRequest {
    mac: String,
}

#[tokio::main]
async fn main() {
    // Initialiser le logger
    SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap();

    let webhook = warp::path("webhook")
        .and(warp::post())
        .and(warp::body::json())
        .map(|request: WebhookRequest| {
            match parse_mac_address(&request.mac) {
                Ok(mac) => {
                    info!("Received request to send WoL packet to MAC: {}", request.mac);
                    if let Err(e) = send_wol_packet(mac) {
                        error!("Failed to send WoL packet: {}", e);
                        warp::reply::with_status("Failed to send WoL packet", warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                    } else {
                        warp::reply::with_status("WoL packet sent", warp::http::StatusCode::OK)
                    }
                }
                Err(e) => {
                    error!("Invalid MAC address format: {}", e);
                    warp::reply::with_status("Invalid MAC address format", warp::http::StatusCode::BAD_REQUEST)
                },
            }
        });

    warp::serve(webhook)
        .run(([0, 0, 0, 0], 8080))  // Utiliser le port 8080
        .await;
}

fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], &'static str> {
    let bytes: Vec<u8> = mac_str.split(':')
        .map(|s| u8::from_str_radix(s, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid MAC address format")?;
    
    if bytes.len() == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes);
        Ok(mac)
    } else {
        Err("Invalid MAC address length")
    }
}

fn send_wol_packet(mac: [u8; 6]) -> Result<(), String> {
    let mut packet = [0u8; 102];
    for i in 0..6 {
        packet[i] = 0xFF;
    }
    for i in 0..16 {
        for j in 0..6 {
            packet[6 + i * 6 + j] = mac[j];
        }
    }

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.set_broadcast(true).map_err(|e| e.to_string())?;
    socket.send_to(&packet, "255.255.255.255:9").map_err(|e| e.to_string())?;
    
    Ok(())
}
