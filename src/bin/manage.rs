#![cfg(feature = "cli")]

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::arg;
use tracing_subscriber::EnvFilter;
use walnut_dns::{
    SqliteStore,
    rr::{Name, Zone, ZoneType},
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
