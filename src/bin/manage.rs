#![cfg(feature = "cli")]

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{ArgGroup, arg};
use tracing_subscriber::EnvFilter;
use walnut_dns::{
    Lookup, SqliteStore, ZoneInfo,
    catalog::CatalogStore as _,
    client::nameserver::{ConnectionConfig, Nameserver, NameserverConfig, ProtocolConfig},
    notify::{NotifyConfig, NotifyManager},
    rr::{DNSClass, Name, RecordSet, RecordType, Zone, ZoneType},
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

    let mut app = clap::Command::new("walnut-dns")
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
            clap::Command::new("show")
                .about("Show a DNS Zone from the walnut database")
                .arg(
                    arg!(<ORIGIN> "DNS origin for zone file")
                        .value_parser(clap::value_parser!(Name)),
                ),
        )
        .subcommand(
            clap::Command::new("notify")
                .about("Notify a downstream DNS server about a given set of records")
                .arg(
                    arg!(<ORIGIN> "DNS origin for the zone for notification")
                        .value_parser(clap::value_parser!(Name)),
                )
                .arg(
                    arg!(<TYPE> "DNS record type to notify")
                        .value_parser(clap::value_parser!(RecordType)),
                )
                .arg(
                    arg!(--class [CLASS] "DNS Class for notification")
                        .value_parser(clap::value_parser!(DNSClass))
                        .default_value("IN"),
                )
                .arg(arg!(--empty "Send an empty notify with no records"))
                .next_help_heading("DNS Connection")
                .arg(
                    arg!(-b --bind <ADDR> "Bind address").value_parser(clap::value_parser!(IpAddr)),
                )
                .arg(
                    arg!(-s --server <SERVER> ... "DNS server to notify")
                        .value_parser(clap::value_parser!(IpAddr)),
                )
                .arg(
                    arg!(--timeout <SECONDS> "Connection timeout")
                        .value_parser(clap::value_parser!(u64))
                        .default_value("10"),
                )
                .arg(
                    arg!(--udp [port] "Use udp (and set port, default 53)")
                        .value_parser(clap::value_parser!(u16))
                        .default_value("53"),
                )
                .arg(
                    arg!(--tcp [port] "Use tcp (and set port, default 53)")
                        .value_parser(clap::value_parser!(u16))
                        .default_value("53"),
                )
                .arg(
                    clap::Arg::new("tls")
                        .long("tls")
                        .action(clap::ArgAction::Append)
                        .value_names(["NAME", "port"])
                        .num_args(1..=2)
                        .help("Use tls with server name (and port, default 853)"),
                )
                .arg(
                    clap::Arg::new("https")
                        .long("https")
                        .action(clap::ArgAction::Append)
                        .value_names(["NAME", "ENDPOINT", "port"])
                        .num_args(2..=3)
                        .help("Use https with server name, endpoint (and port, default 853)"),
                )
                .group(
                    ArgGroup::new("protocol")
                        .required(true)
                        .multiple(true)
                        .args(["udp", "tcp", "tls", "https"]),
                ),
        );

    let no_connections_error = app.error(
        clap::error::ErrorKind::MissingRequiredArgument,
        "No connections configured. Configure at least one connection",
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
        Some(("show", matches)) => {
            let name = matches
                .get_one::<Name>("ORIGIN")
                .expect("ORIGIN is required");
            match show_zone_from_db(db, name) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error showing zone from {}:", name);
                    eprintln!("{error}");
                    return Err(());
                }
            }
        }
        Some(("notify", matches)) => {
            let name = matches
                .get_one::<Name>("ORIGIN")
                .expect("ORIGIN is required");
            let record_type = matches
                .get_one::<RecordType>("TYPE")
                .expect("TYPE is required");
            let class = matches
                .get_one::<DNSClass>("class")
                .expect("CLASS is required");
            let servers = matches
                .get_many::<IpAddr>("server")
                .expect("SERVER is required")
                .copied()
                .collect::<Vec<_>>();
            let bind = matches.get_one::<IpAddr>("bind").copied();

            let empty = matches.get_flag("empty");

            let connections = parse_protocol_matches(matches);

            if connections.is_empty() {
                eprintln!("{no_connections_error}");
                return Err(());
            }

            match notify_servers(
                db,
                name,
                record_type,
                class,
                empty,
                bind,
                &servers,
                connections,
            ) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error notifying servers:");
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

fn parse_protocol_matches(matches: &clap::ArgMatches) -> Vec<ConnectionConfig> {
    let mut connections = Vec::new();

    let timeout = matches.get_one::<u64>("timeout").copied();

    fn simple_occurences(
        matches: &clap::ArgMatches,
        id: &str,
        protocol: ProtocolConfig,
        timeout: Option<u64>,
    ) -> Vec<ConnectionConfig> {
        let mut connections = Vec::new();
        if let Some(occurences) = matches.get_occurrences(id) {
            for mut occurence in occurences {
                let port = occurence.next().unwrap_or(&53);

                connections.push(ConnectionConfig {
                    protocol: protocol.clone(),
                    port: *port,
                    timeout,
                });
            }
        }
        connections
    }

    connections.extend(simple_occurences(
        matches,
        "udp",
        ProtocolConfig::Udp,
        timeout,
    ));
    connections.extend(simple_occurences(
        matches,
        "tcp",
        ProtocolConfig::Tcp,
        timeout,
    ));

    #[allow(unused_variables)]
    if let Some(occurences) = matches.get_occurrences::<String>("tls") {
        #[cfg(feature = "tls")]
        {
            for occurence in occurences {
                let mut parts: Vec<_> = occurence.rev().collect();
                let Some(name) = parts.pop() else {
                    eprintln!("--tls missing server name");
                    continue;
                };

                let port = if let Some(port_raw) = parts.pop() {
                    match port_raw.parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => {
                            eprintln!("--tls invalid port number: {}", port_raw);
                            continue;
                        }
                    }
                } else {
                    853
                };

                connections.push(ConnectionConfig {
                    protocol: ProtocolConfig::Tls {
                        server_name: name.clone().into_boxed_str(),
                    },
                    port,
                    timeout,
                });
            }
        }

        #[cfg(not(feature = "tls"))]
        {
            eprintln!("--tls feature not enabled");
        }
    }

    #[allow(unused_variables)]
    if let Some(occurences) = matches.get_occurrences::<String>("https") {
        #[cfg(feature = "h2")]
        {
            for occurence in occurences {
                let mut parts: Vec<_> = occurence.rev().collect();
                let Some(name) = parts.pop() else {
                    eprintln!("--https missing server name");
                    continue;
                };

                let Some(endpoint) = parts.pop() else {
                    eprintln!("--https missing server endpoint");
                    continue;
                };

                let port = if let Some(port_raw) = parts.pop() {
                    match port_raw.parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => {
                            eprintln!("--https invalid port number: {}", port_raw);
                            continue;
                        }
                    }
                } else {
                    443
                };

                connections.push(ConnectionConfig {
                    protocol: ProtocolConfig::Https {
                        server_name: name.clone().into_boxed_str(),
                        endpoint: endpoint.clone().into_boxed_str(),
                    },
                    port,
                    timeout,
                });
            }
        }
        #[cfg(not(feature = "h2"))]
        {
            eprintln!("--https requires the h2 feature");
        }
    }

    connections
}

fn notify_servers(
    db: &Path,
    origin: &Name,
    record_type: &RecordType,
    class: &DNSClass,
    empty: bool,
    bind: Option<IpAddr>,
    servers: &[IpAddr],
    connections: Vec<ConnectionConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    rt.block_on(async {
        let connection = rusqlite::Connection::open(db)?;
        let catalog = SqliteStore::new(connection.into()).await?;

        let zones = catalog.find(&origin.clone().into()).await?;

        let Some(zone) = zones.and_then(|zones| zones.into_iter().find(|z| *z.name() == *origin))
        else {
            return Err(format!("Zone {origin} not found").into());
        };

        let nameservers = servers
            .iter()
            .copied()
            .map(|address| {
                Nameserver::new(
                    NameserverConfig {
                        address,
                        connections: connections.clone(),
                        policy: Default::default(),
                    },
                    bind,
                )
            })
            .collect();
        let mut notify = NotifyManager::new(nameservers, NotifyConfig::default());

        if empty {
            notify
                .notify::<RecordSet>(
                    origin.clone(),
                    *class,
                    *record_type,
                    None,
                    Default::default(),
                )
                .await?;
        } else {
            for rrset in Lookup::records(&*zone)
                .filter(|r| r.record_type() == *record_type && r.dns_class() == *class)
            {
                println!(
                    "Notify {} {} {}",
                    rrset.record_type(),
                    rrset.dns_class(),
                    rrset.name()
                );
                notify
                    .notify(
                        origin.clone(),
                        *class,
                        *record_type,
                        Some(rrset.clone()),
                        Default::default(),
                    )
                    .await?;
            }
        }

        Ok(())
    })
}

fn show_zone_from_db(db: &Path, zone: &Name) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let connection = rusqlite::Connection::open(db)?;
        let catalog = SqliteStore::new(connection.into()).await?;

        let zones = catalog.find(&zone.clone().into()).await?;

        let Some(zone) = zones.and_then(|zones| zones.into_iter().find(|z| *z.name() == *zone))
        else {
            return Err(format!("Zone {zone} not found").into());
        };

        println!("Zone: {}", zone.origin());
        for rrset in Lookup::records(&*zone) {
            for record in rrset.records() {
                println!(
                    "{} {} {}: {}",
                    record.record_type(),
                    record.dns_class(),
                    record.name(),
                    record.rdata()
                );
            }
        }

        Ok(())
    })
}
