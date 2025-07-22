use std::{net::IpAddr, path::PathBuf};

use chateau::server::Server;
use clap::arg;
use tracing_subscriber::EnvFilter;
use walnut_dns::{
    Catalog, SqliteStore,
    server::udp::{DnsOverUdp, UdpListener},
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cmd = clap::Command::new("serve")
        .about("Run a DNS server")
        .arg(
            arg!(--db <DATABASE> "Path to an SQLite Walnut-DNS Database")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            arg!(--port <PORT> "Port to listen on")
                .value_parser(clap::value_parser!(u16))
                .default_value("8053"),
        )
        .arg(
            arg!(--address <ADDRESS> "Address to listen on")
                .value_parser(clap::value_parser!(IpAddr))
                .default_value("127.0.0.1"),
        );

    let args = cmd.get_matches();
    let db = args.get_one::<PathBuf>("db").expect("db is required");
    let address = args
        .get_one::<IpAddr>("address")
        .expect("address is required");
    let port = args.get_one::<u16>("port").expect("port is required");

    if let Err(error) = server(*address, *port, db).await {
        eprintln!("{error}");
        Err(())
    } else {
        Ok(())
    }
}

async fn server(
    address: IpAddr,
    port: u16,
    db: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
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
