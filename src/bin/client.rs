use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use clap::arg;
use hickory_proto::{op::Query, rr::RecordType, xfer::DnsRequestOptions};
use tracing::trace;
use tracing_subscriber::EnvFilter;
use walnut_dns::client::ClientConfiguration;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cmd = clap::Command::new("walnut-client")
        .about("Simple DNS Client")
        .arg(
            arg!(--db <DATABASE> "Path to SQLite Database for cache")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            arg!(--cfg <PATH> "DNS Configuration file to use")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(arg!(<QUERY> "DNS Name to query"))
        .arg(
            arg!([TYPE] "DNS record type to query")
                .value_parser(clap::value_parser!(RecordType))
                .default_value("A"),
        );

    let args = cmd.get_matches();
    let config_path = args
        .get_one::<PathBuf>("cfg")
        .cloned()
        .unwrap_or("walnut.toml".into());

    let query = args.get_one::<String>("QUERY").expect("query is required");
    let record_type = args
        .get_one::<RecordType>("TYPE")
        .expect("type is required");

    let cache = if let Some(database) = args.get_one::<PathBuf>("db") {
        let connection = rusqlite::Connection::open(database).expect("unable to open db");
        Some(
            walnut_dns::cache::DnsCache::new(connection.into(), Default::default())
                .await
                .unwrap(),
        )
    } else {
        None
    };

    if let Err(error) = lookup(&config_path, query, *record_type, cache).await {
        eprintln!("{error}");
        Err(())
    } else {
        Ok(())
    }
}

async fn lookup(
    config: &Path,
    query: &str,
    record: RecordType,
    cache: Option<walnut_dns::cache::DnsCache>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_file: Vec<u8> = tokio::fs::read(config).await?;
    let config: ClientConfiguration = toml_edit::de::from_slice(&config_file)?;

    let mut client = walnut_dns::client::Client::new(config);
    if let Some(cache) = &cache {
        client = client.with_cache(cache.clone());
    }
    trace!("client constructed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let query = Query::query(query.parse()?, record);
    trace!("client send request");
    let response = client.lookup(query, DnsRequestOptions::default()).await?;

    response.queries().iter().for_each(|query| {
        println!(
            "Query: {} {} {}",
            query.name(),
            query.query_class(),
            query.query_type()
        );
    });

    if response.answer_count() > 0 {
        println!("Answers:");
    }
    response.answers().iter().for_each(|answer| {
        println!(
            "{} {} {}",
            answer.name(),
            answer.record_type(),
            answer.data()
        )
    });

    if let Some(cache) = cache {
        cache.cleanup(Utc::now()).await?;
    }

    Ok(())
}
