#![cfg(feature = "cli")]

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use chateau::server::Server;
use clap::arg;
use tracing_subscriber::EnvFilter;
use walnut_dns::{
    Catalog, SqliteStore,
    rr::{Name, Zone, ZoneType},
    server::udp::{DnsOverUdp, UdpListener},
};

fn main() -> ExitCode {
    match manage() {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn manage() -> Result<(), ()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = clap::Command::new("walnut-dns")
        .about("Manage the walnut-dns database")
        .args([arg!(--db <PATH> "Path to the walnut DB")
            .required(true)
            .value_parser(clap::value_parser!(PathBuf))])
        .subcommand(
            clap::Command::new("load-zone")
                .about("Load a zone file into the walnut database")
                .arg(arg!(<ZONE> "Zone file to load").value_parser(clap::value_parser!(PathBuf)))
                .arg(
                    arg!(<ORIGIN> "DNS origin for zone file")
                        .value_parser(clap::value_parser!(Name)),
                ),
        )
        .subcommand(
            clap::Command::new("serve")
                .about("Run a DNS server")
                .arg(
                    arg!(--port <PORT> "Port to listen on")
                        .value_parser(clap::value_parser!(u16))
                        .default_value("8053"),
                )
                .arg(
                    arg!(--address <ADDRESS> "Address to listen on")
                        .value_parser(clap::value_parser!(IpAddr))
                        .default_value("127.0.0.1"),
                ),
        );

    let args = app.get_matches();
    let db: &PathBuf = args.get_one("db").expect("db is required");

    match args.subcommand() {
        Some(("load-zone", matches)) => {
            let zone_file = matches
                .get_one::<PathBuf>("ZONE")
                .expect("ZONE is required");
            let name = matches
                .get_one::<Name>("ORIGIN")
                .expect("ORIGIN is required");
            match load_zone_to_db(db, zone_file, name) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error loading zone from {}:", zone_file.display());
                    eprintln!("{error}");
                    return Err(());
                }
            }
        }
        Some(("serve", matches)) => {
            let address = matches
                .get_one::<IpAddr>("address")
                .expect("address is required");
            let port = matches.get_one::<u16>("port").expect("port is required");
            match serve_dns(*address, *port, db) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error in DNS server");
                    eprintln!("{error}");
                    return Err(());
                }
            }
        }
        _ => unreachable!("clap crimes?"),
    }

    Ok(())
}

fn load_zone_to_db(
    db: &Path,
    zone_file: &Path,
    origin: &Name,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let connection = rusqlite::Connection::open(db)?;
        let catalog = SqliteStore::new(connection.into()).await?;

        let zone = Zone::read_from_file(origin.clone(), zone_file, ZoneType::External)?;
        catalog.insert(&zone).await?;
        println!("Zone '{}' loaded successfully", zone.name());
        Ok(())
    })
}

fn serve_dns(address: IpAddr, port: u16, db: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(address, port, db.to_path_buf()))
}

async fn serve(address: IpAddr, port: u16, db: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(db)?;
    let store = SqliteStore::new(connection.into()).await?;
    let catalog = Catalog::new(store);

    let socket = tokio::net::UdpSocket::bind((address, port)).await?;
    let server = Server::builder()
        .with_shared_service(catalog)
        .with_acceptor(UdpListener::new(socket.into()))
        .with_protocol(DnsOverUdp::new())
        .with_tokio()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });

    println!("Server started on {address}:{port}");
    server.await?;
    println!("...end");
    Ok(())
}
